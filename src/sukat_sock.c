/*!
 * @file sukat.c
 * @brief Implentation of sukat socket API.
 *
 * @addtogroup sukat_api
 * @{
 */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <linux/tipc.h>
#include <sys/un.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/epoll.h>

#include "sukat_sock.h"
#include "sukat_log_internal.h"
#include "sukat_tree.h"

/*!
 * Structure used to store either partially sent data or partially received
 * data.
 */
struct rw_cache
{
  uint8_t *data; //!< Data area.
  size_t len; //!< How much is read or how much is left to send.
};

struct client_ctx
{
  int fd; //!< Accepted fd.
  void *client_caller_ctx; //!< Specific context if set. Otherwise NULL.
  sukat_sock_ctx_t *main_ctx; //!< Backwards pointer to sukat_sock_ctx_t.
  bool in_callback; //!< If true, don't delete this immediately as we might
  bool destroyed; //!< If true, destroy on first chance.
  bool waiting_on_write; //!< If true EPOLLOUT is set
  sukat_tree_node_t *node;
  struct rw_cache cache;
};

struct sukat_sock_ctx
{
  union
    {
      struct sockaddr_storage storage;
      struct sockaddr_in sin;
      struct sockaddr_in6 sin6;
      struct sockaddr_un sun;
      struct sockaddr_tipc stipc;
    };
  struct sukat_sock_cbs cbs;
  int fd; //!< Main fd for accept to server or connected fd for client.
  void *caller_ctx; //!< If true, dont delete immediately.
  sukat_tree_ctx_t *client_tree; //!< Tree of active clients sorted by fd.
  sukat_tree_ctx_t *removed_tree; /*!< Tree collected during callbacks where
                                       clients were destroyd */
  bool connect_in_progress; //! If set, a connect returned EINPROCESS
  bool is_server; //!< True for server operation.
  bool in_callback; //!< If true, don't destroy oneself immediately.
  bool destroyed; //!< If true, don't destroy oneself immediately.
  size_t n_connections;
  int epoll_fd;
  int master_epoll_fd;
  int domain;
  int type;
  struct rw_cache cache;
};

static bool socket_connection_oriented(int type)
{
  if (type == SOCK_DGRAM || type == SOCK_RDM)
    {
      return false;
    }
  return true;
}

static char *socket_log(sukat_sock_ctx_t *ctx, struct sukat_sock_params *params,
                        char *buf, size_t buf_len)
{
  size_t n_used = 0;
  int domain = (params) ? params->domain : ctx->domain;
  bool is_abstract = (params) ? params->punix.is_abstract :
    (ctx->sun.sun_path[0] == '\0');
  uint32_t port_type = (params) ? params->ptipc.port_type :
    ctx->stipc.addr.nameseq.type;
  uint32_t port_instance = (params) ? params->ptipc.port_instance :
    ctx->stipc.addr.nameseq.lower;
  const char *unix_path = (params) ? params->punix.name : (is_abstract) ?
    ctx->sun.sun_path + 1 : ctx->sun.sun_path;
  int type = (params) ? params->type : ctx->type;

  assert(ctx != NULL && buf != NULL && buf_len > 0);
#define SAFEPUT(...)                                                          \
  do                                                                          \
    {                                                                         \
      n_used += snprintf(buf + n_used, buf_len - n_used, __VA_ARGS__);        \
      if (n_used >= buf_len)                                                  \
        {                                                                     \
          return buf;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)

  switch(type)
    {
    case SOCK_STREAM:
      SAFEPUT("Stream ");
      break;
    case SOCK_DGRAM:
        SAFEPUT("Datagram ");
      break;
    case SOCK_SEQPACKET:
      SAFEPUT("Seqpacket ");
      break;
    default:
      SAFEPUT("Unknown type %d", type);
      break;
    }

  SAFEPUT((ctx->is_server) ? "server ": "client ");
  switch (domain)
    {
    case AF_UNIX:
      SAFEPUT("UNIX %s%s", (is_abstract) ? "abstract " : "", unix_path);
      break;
    case AF_TIPC:
      SAFEPUT("TIPC type %d service %d", port_type, port_instance);
      break;
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      SAFEPUT("INET %s:%s", (params) ? params->pinet.ip : "TODO", 
              (params) ? params->pinet.port : "TODO");
      break;
    default:
      SAFEPUT("Unknown %d", params->domain);
      break;
    }

  return buf;
}

static void free_cache(struct rw_cache *cache)
{
  assert(cache != NULL);
  free(cache->data);
  memset(cache, 0, sizeof(*cache));
}

static bool cache_to(struct rw_cache *cache, uint8_t *buf, size_t buf_amount)
{
  assert(cache->data == NULL);
  cache->data = (uint8_t *)malloc(buf_amount);
  if (!cache->data)
    {
      return false;
    }
  memcpy(cache->data, buf, buf_amount);
  cache->len = buf_amount;
  return true;
}

static bool cache(sukat_sock_ctx_t *ctx, struct client_ctx *client,
                  uint8_t *buf, size_t buf_amount)
{
  bool ret;

  assert(ctx != NULL && buf != NULL);
  if(!buf_amount)
    {
      return true;
    }
  if (client)
    {
      ret = cache_to(&client->cache, buf, buf_amount);
    }
  else
    {
      ret = cache_to(&ctx->cache, buf, buf_amount);
    }
  if (ret == false)
    {
      ERR(ctx, "Cannot cache data: %s", strerror(errno));
    }
  return ret;
}

static void uncache_from(struct rw_cache *cache, uint8_t *buf, size_t *uncached)
{
  if (!cache->data)
    {
      assert(cache->len == 0);
      return;
    }
  memcpy(buf, cache->data, cache->len);
  *uncached = cache->len;
  free_cache(cache);
}

static void uncache(sukat_sock_ctx_t *ctx, struct client_ctx *client,
                    uint8_t *buf, size_t *uncached)
{
  assert(ctx != NULL && buf != NULL && uncached != NULL);
  if (client)
    {
      uncache_from(&client->cache, buf, uncached);
    }
  else
    {
      uncache_from(&ctx->cache, buf, uncached);
    }
}

static void enter_cb(sukat_sock_ctx_t *ctx)
{
  ctx->in_callback = true;
}

static void leave_cb(sukat_sock_ctx_t *ctx)
{
  ctx->in_callback = false;
  if (ctx->destroyed)
    {
      sukat_sock_destroy(ctx);
    }
}

/*!
 * Set O_CLOEXEC and O_NONBLOCK
 */
static bool set_flags(sukat_sock_ctx_t *ctx, int fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    {
      ERR(ctx, "Failed to get flags for fd %d: %s", fd, strerror(errno));
      return false;
    }
  flags |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, flags) != 0)
    {
      ERR(ctx, "Failed to set non-blocking to fd %d: %s", fd, strerror(errno));
      return false;
    }
  flags = fcntl(fd, F_GETFD, 0);
  if (flags < 0)
    {
      ERR(ctx, "Failed to getfd for fd %d: %s", fd, strerror(errno));
      return false;
    }
  flags |= FD_CLOEXEC;
  if (fcntl(fd, F_SETFD, flags) != 0)
    {
      ERR(ctx, "Failed to set cloexec on fd %d: %s", fd, strerror(errno));
      return false;
    }
  return true;
}

static void socket_fill_tipc(struct sukat_sock_params *params,
                             struct sockaddr_tipc *tipc,
                             socklen_t *addrlen)
{
  tipc->family = AF_TIPC;
  if (params->server)
    {
      tipc->addrtype = TIPC_ADDR_NAMESEQ;
      tipc->addr.nameseq.lower = params->ptipc.port_instance;
      tipc->addr.nameseq.upper = params->ptipc.port_instance;
      tipc->scope = params->ptipc.scope;
      tipc->addr.nameseq.type = params->ptipc.port_type;
    }
  else
    {
      tipc->addrtype = TIPC_ADDR_NAME;
      tipc->addr.name.name.instance =
        params->ptipc.port_instance;
      tipc->addr.name.domain = 0;
      tipc->addr.name.name.type = params->ptipc.port_type;
    }
  *addrlen = sizeof(*tipc);
}

static bool socket_fill_unix(sukat_sock_ctx_t *ctx,
                             struct sukat_sock_params *params,
                             struct sockaddr_un *sun, socklen_t *addrlen)
{
  size_t n_used = 0;
  if (params->punix.name == NULL)
    {
      ERR(ctx, "No name given for AF_UNIX socket");
      return false;
    }
  sun->sun_family = AF_UNIX;
  if (params->punix.is_abstract)
    {
      *sun->sun_path = '\0';
    }
  snprintf(sun->sun_path + n_used, sizeof(sun->sun_path) -
           n_used - 1, "%s", params->punix.name);
  *addrlen = sizeof(*sun);

  return true;
}

static int socket_create(sukat_sock_ctx_t *ctx,
                         struct sukat_sock_params *params)
{
  int fd = -1;
  union {
      struct sockaddr_tipc tipc;
      struct sockaddr_un un;
  } sockaddr;
  socklen_t addrlen = 0;
  char socket_buf[128];
  int type = params->type;

  memset(&sockaddr, 0, sizeof(sockaddr));
  type |= SOCK_NONBLOCK | SOCK_CLOEXEC;
  LOG(ctx, "%s: Creating", socket_log(ctx, params, socket_buf,
                                      sizeof(socket_buf)));
  fd = socket(params->domain, type, 0);
  if (fd <= 0)
    {
      ERR(ctx, "Failed to create socket: %s", strerror(errno));
      goto fail;
    }
  if (params->domain == AF_UNIX)
    {
      if (socket_fill_unix(ctx, params, &sockaddr.un, &addrlen) != true)
        {
          goto fail;
        }
    }
  else if (params->domain == AF_TIPC)
    {
      socket_fill_tipc(params, &sockaddr.tipc, &addrlen);
    }
  else
    {
      ERR(ctx, "Not implemented");
      goto fail;
    }
  if (params->server)
    {
      if (bind(fd, (struct sockaddr *)&sockaddr, addrlen) != 0)
        {
          ERR(ctx, "Failed to bind to socket: %s", strerror(errno));
          goto fail;
        }
      if (socket_connection_oriented(params->type))
        {
          if (params->listen == 0)
            {
              params->listen = SOMAXCONN;
            }
          if (listen(fd, params->listen) != 0)
            {
              ERR(ctx, "Failed to listen to socket: %s", strerror(errno));
              goto fail;
            }
        }
    }
  else
    {
      if (connect(fd, (struct sockaddr *)&sockaddr, addrlen) != 0)
        {
          if (errno == EINPROGRESS)
            {
              DBG(ctx, "Connect not completed with a single call");
              ctx->connect_in_progress = true;
            }
          else
            {
              ERR(ctx, "Failed to connect to end-point: %s", strerror(errno));
              goto fail;
            }
        }
    }
  memcpy(&ctx->sin, &sockaddr, sizeof(sockaddr));

  LOG(ctx, "%s created", socket_log(ctx, params, socket_buf,
                                    sizeof(socket_buf)));

  //TODO save some sockaddr_storage for debugging as union of parameters.*/
  ctx->n_connections++;

  return fd;

fail:
  if (fd >= 0)
    {
      close(fd);
    }
  return -1;
}

void read_client_cb(void *cctx, int fd, uint32_t events)
{
  struct client_ctx *client = (struct client_ctx *)cctx;
  sukat_sock_ctx_t *ctx = client->main_ctx;

  DBG(ctx, "FD %d received events %u", fd, events);
  //TODO:
}

static bool event_ctl(int epoll_fd, int fd, void *data, int op, uint32_t events)
{
  struct epoll_event event =
    {
      .events = events,
      .data =
        {
          .ptr = data,
        }
    };

  assert(op == EPOLL_CTL_ADD || op == EPOLL_CTL_DEL ||
         op == EPOLL_CTL_MOD);
  if (epoll_ctl(epoll_fd, op, fd, &event) != 0) {
      return false;
  }
  return true;
}

static bool event_add_to_ctx(sukat_sock_ctx_t *ctx, int fd, void *data, int op,
                             uint32_t events) {
    if (event_ctl(ctx->epoll_fd, fd, data, op, events) != true)
      {
        ERR(ctx, "Failed to add fd %d events %u: %s", fd, events,
            strerror(errno));
        return false;
      }
    return true;
}

static void *get_caller_ctx(sukat_sock_ctx_t *ctx, struct client_ctx *client)
{
  if (client && client->client_caller_ctx)
    {
      return client->client_caller_ctx;
    }
  return ctx->caller_ctx;
}

static void client_close(sukat_sock_ctx_t *ctx, struct client_ctx *client)
{
  uint32_t events = EPOLLIN;
  void *caller_ctx = get_caller_ctx(ctx, client);

  LOG(ctx, "Removing client %d", client->fd);
  if (client->waiting_on_write)
    {
      events |= EPOLLOUT;
    }
  event_ctl(ctx->epoll_fd, client->fd, NULL, EPOLL_CTL_DEL, events);
  free_cache(&client->cache);
  close(client->fd);
  if (!client->destroyed && ctx->cbs.conn_cb)
    {
      ctx->cbs.conn_cb(caller_ctx, ctx->fd, NULL, 0, true);
    }
  ctx->n_connections--;
  free(client);
}

static void server_accept_cb(sukat_sock_ctx_t *ctx)
{
  struct sockaddr_storage saddr;
  socklen_t slen = sizeof(saddr);
  struct client_ctx *client;
  int fd;

  fd = accept(ctx->fd, (struct sockaddr *)&saddr, &slen);
  if (fd < 0)
    {
      ERR(ctx, "Failed to accept: %s", strerror(errno));
      return;
    }
  LOG(ctx, "New client with fd %d", fd);
  client = (struct client_ctx *)calloc(1, sizeof(*client));
  if (!client)
    {
      ERR(ctx, "No memory to accept new clients: %s", strerror(errno));
      close(fd);
      return;
    }
  client->fd = fd;
  client->main_ctx = ctx;

  if (event_add_to_ctx(ctx, fd, client, EPOLL_CTL_ADD, EPOLLIN) != true)
    {
      close(fd);
      free(client);
      return;
    }
  if (ctx->cbs.conn_cb)
    {
       client->client_caller_ctx =
         ctx->cbs.conn_cb(ctx->caller_ctx, fd, &saddr, slen, false);
    }
  ctx->n_connections++;
}

static bool client_continue_connect(sukat_sock_ctx_t *ctx)
{
  socklen_t slen;

  switch (ctx->domain)
    {
    case AF_TIPC:
      slen = sizeof(ctx->stipc);
      break;
    case AF_UNIX:
      slen = sizeof(ctx->sun);
      break;
    case AF_INET:
      slen = sizeof(ctx->sin);
      break;
    case AF_INET6:
      slen = sizeof(ctx->sin6);
      break;
    default:
      ERR(ctx, "domain %d not implemented for continued connect",
          ctx->domain);
      return false;
    }

  if (connect(ctx->fd, (struct sockaddr *)&ctx->storage, slen) != 0)
    {
      if (errno == EINPROGRESS)
        {
          DBG(ctx, "Connect still in progress");
        }
      else
        {
          ERR(ctx, "Connect continuing failed: %s", strerror(errno));
          //TODO. Need a error callback.
        }
      return false;
    }
  else
    {
      LOG(ctx, "Connected!");
      ctx->connect_in_progress = false;
    }
  return true;
}

typedef enum event_handling_ret
{
  ERR_FATAL = -1,
  ERR_OK = 0,
  ERR_BREAK = 1,
} ret_t;

static bool keep_going(sukat_sock_ctx_t *ctx,
                       struct client_ctx *client)
{
  if (ctx->destroyed || (client && client->destroyed))
    {
      return false;
    }
  return true;
}

#define BUF_LEFT (sizeof(buf) - n_read)
#define UNPROCESSED (n_read - processed)

static ret_t read_stream(sukat_sock_ctx_t *ctx, struct client_ctx *client)
{
  size_t n_read = 0;
  uint8_t buf[BUFSIZ];
  int fd = (client) ? client->fd : ctx->fd;
  ssize_t read_now;
  size_t processed = 0;
  void *caller_ctx = get_caller_ctx(ctx, client);
  int client_id = (client) ? client->fd : 0;

  uncache(ctx, client, buf, &n_read);

  do
    {
      read_now = read(fd, buf + n_read, BUF_LEFT);
    } while (read_now > 0 && (n_read += read_now) < sizeof(buf));
  if (read_now <= 0)
    {
      if (!(read_now == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)))
        {
          ERR(ctx, "Connection %s%s", (read_now == 0) ? "closed" :
              "severed: ", (read_now == -1) ? strerror(errno) : "");
          if (ctx->cbs.error_cb)
            {
              ctx->cbs.error_cb(caller_ctx, client_id, errno);
            }
          return ERR_FATAL;
        }
    }

  while (UNPROCESSED && keep_going(ctx, client))
    {
      size_t msg_len = 0;

      if (ctx->cbs.msg_len_cb)
        {
          int msg_len_query = ctx->cbs.msg_len_cb(caller_ctx, buf + processed,
                                                  UNPROCESSED);
          if (msg_len_query < 0)
            {
              ERR(ctx, "Corruption detected by caller");
              return ERR_FATAL;
            }
          else if (msg_len_query == 0)
            {
              if (cache(ctx, client, buf + processed, UNPROCESSED) != true)
                {
                  if (ctx->cbs.error_cb)
                    {
                      ctx->cbs.error_cb(caller_ctx, client_id, ENOMEM);
                    }
                  return ERR_FATAL;
                }
              return ERR_OK;
            }
          msg_len = (size_t)msg_len_query;
        }
      else
        {
          ERR(ctx, "Stream oriented without a msg_len_cb not implemented");
          return ERR_FATAL;
        }
      if (ctx->cbs.msg_cb)
        {
          ctx->cbs.msg_cb(caller_ctx, client_id, buf + processed, msg_len);
        }
      processed += msg_len;
    }

  return ERR_OK;
}

static ret_t read_seqpacket(sukat_sock_ctx_t *ctx, struct client_ctx *client)
{
  ERR(ctx, "Not implemented");
  (void)client;
  return ERR_FATAL;
}

static ret_t read_connectionless(sukat_sock_ctx_t *ctx,
                                 struct client_ctx *client)
{
  ERR(ctx, "Not implemented");
  (void)client;
  return ERR_FATAL;
}

static ret_t event_read(sukat_sock_ctx_t *ctx,
                        struct client_ctx *client)
{
  if (socket_connection_oriented(ctx->type))
    {
      if (ctx->type == SOCK_SEQPACKET)
        {
          return read_seqpacket(ctx, client);
        }
      else
        {
          return read_stream(ctx, client);
        }
    }
  return read_connectionless(ctx, client);
}

static void event_non_epollin(sukat_sock_ctx_t *ctx,
                              struct client_ctx *client, uint32_t events)
{
  void *caller_ctx = get_caller_ctx(ctx, client);

  ERR(ctx, "%s event received from %s connection",
      (events == EPOLLERR) ? "Error" : "Disconnect",
      (client) ? "client" : "main");
  if (ctx->cbs.error_cb)
    {
      int errval = (events & EPOLLIN) ? ECONNABORTED :
        ECONNRESET;

      ctx->cbs.error_cb(caller_ctx, -1, errval);
    }
}

static ret_t event_handle(sukat_sock_ctx_t *ctx, struct epoll_event *event)
{
  if (event->data.ptr == (void *)ctx)
    {
      if (event->events != EPOLLIN)
        {
          event_non_epollin(ctx, NULL, event->events);
          return ERR_FATAL;
        }
      if (!ctx->is_server && ctx->connect_in_progress)
        {
          if (client_continue_connect(ctx) != true)
            {
              return ERR_OK;
            }
        }
      else if (ctx->is_server)
        {
          server_accept_cb(ctx);
        }
      else
        {
          return event_read(ctx, NULL);
        }
    }
  else
    {
      struct client_ctx *client = (struct client_ctx *)(event->data.ptr);

      client->in_callback = true;

      if (event->events != EPOLLIN)
        {
          event_non_epollin(ctx, client, event->events);
          client->in_callback = false;
          client_close(ctx, client);
        }
      else
        {
          ret_t ret;
          ret = event_read(ctx, client);

          if (ret != ERR_OK || client->destroyed)
            {
              client->in_callback = false;
              client_close(ctx, client);
            }
        }
    }

  return ERR_OK;
}

/*TODO: Not sure if events can be other than EPOLLIN if the slave
 * fds have other than EPOLLIN */
int sukat_sock_read(sukat_sock_ctx_t *ctx, int epoll_fd,
                    __attribute__((unused))uint32_t events,
                    int timeout)
{
  int nfds;
  ret_t ret = ERR_OK;

  if (!ctx || ctx->epoll_fd != epoll_fd)
    {
      ERR(ctx, "sukat API given wrong epoll fd %d instead of %d",
          epoll_fd, ctx->epoll_fd);
      errno = EINVAL;
      return -1;
    }
  enter_cb(ctx);
  do
    {
      struct epoll_event new_events[(ctx->n_connections < 128) ?
        ctx->n_connections : 128];
      size_t i;

      nfds = epoll_wait(ctx->epoll_fd, new_events,
                        sizeof(new_events)/sizeof(*new_events), timeout);
      if (nfds < 0)
        {
          ERR(ctx, "Failed to wait for events: %s", strerror(errno));
          ret = ERR_FATAL;
          goto out;
        }
      for (i = 0; i < (size_t)nfds; i++)
        {
          ret = event_handle(ctx, &new_events[i]);
          if (ret == ERR_FATAL)
            {
              goto out;
            }
          else if (ret == ERR_BREAK)
            {
              ret = ERR_OK;
              goto out;
            }
        }
    } while (nfds > 0 && ctx->destroyed != true && ctx->n_connections > 0);

out:
  leave_cb(ctx);
  return (int)ret;
}

sukat_sock_ctx_t *sukat_sock_create(struct sukat_sock_params *params,
                                    struct sukat_sock_cbs *cbs)
{
  sukat_sock_ctx_t *ctx;

  if (!params)
    {
      if (cbs && cbs->log_cb)
        {
          cbs->log_cb(SUKAT_LOG_ERROR, "No parameters given");
        }
      return NULL;
    }

  ctx = (sukat_sock_ctx_t *)calloc(1, sizeof(*ctx));
  if (!ctx)
    {
      return NULL;
    }
  ctx->fd = ctx->epoll_fd = ctx->master_epoll_fd = -1;
  ctx->is_server = params->server;
  ctx->domain = params->domain;
  ctx->type = params->type;
  ctx->caller_ctx = params->caller_ctx;
  if (cbs)
    {
      memcpy(&ctx->cbs, cbs, sizeof(*cbs));
    }
  ctx->fd = socket_create(ctx, params);
  if (ctx->fd < 0)
    {
      goto fail;
    }
  ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (!ctx->epoll_fd) {
      ERR(ctx, "Failed to create epoll fd: %s", strerror(errno));
      goto fail;
  }
  if (params->master_epoll_fd_set)
    {
      if (event_ctl(params->master_epoll_fd, ctx->epoll_fd, ctx,
                    EPOLL_CTL_ADD, EPOLLIN) != true)
        {
          ERR(ctx, "Failed to add epoll fd %d to master epoll fd %d: %s",
              ctx->epoll_fd, params->master_epoll_fd, strerror(errno));
          goto fail;
        }
      ctx->master_epoll_fd = params->master_epoll_fd;
    }
  if (event_add_to_ctx(ctx, ctx->fd, ctx, EPOLL_CTL_ADD, EPOLLIN) != true)
    {
      goto fail;
    }

  return ctx;

fail:
  sukat_sock_destroy(ctx);
  return NULL;
}

void sukat_sock_destroy(sukat_sock_ctx_t *ctx)
{
  if (ctx)
    {
      if (ctx->in_callback)
        {
          LOG(ctx, "Delaying destruction");
          ctx->destroyed = true;
          return;
        }
      if (ctx->fd >= 0)
        {
          close(ctx->fd);
        }
      if (ctx->master_epoll_fd != -1)
        {
          if (event_ctl(ctx->master_epoll_fd, ctx->epoll_fd, ctx, EPOLL_CTL_DEL,
                        EPOLLIN) != true) {
              ERR(ctx, "Failed to remove epoll_fd from master fd: %s",
                  strerror(errno));
          }
        }
      if (ctx->client_tree)
        {
          sukat_tree_destroy(ctx->client_tree);
          // TODO: destroy stuff in da tree.
        }
      if (ctx->epoll_fd > 0)
        {
          close(ctx->epoll_fd);
        }
      free_cache(&ctx->cache);
      free(ctx);
    }
}

int sukat_sock_get_epoll_fd(sukat_sock_ctx_t *ctx)
{
  if (ctx)
    {
      return ctx->epoll_fd;
    }
  errno = EINVAL;
  return -1;
}

/*! }@ */
