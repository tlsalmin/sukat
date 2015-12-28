/*!
 * @file sukat_sock.c
 * @brief Implentation of sukat socket API.
 *
 * @addtogroup sukat_sock
 * @{
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
#include <netdb.h>
#include <arpa/inet.h>

#include "sukat_sock.h"
#include "sukat_log_internal.h"
#include "sukat_drawer.h"

/*!
 * Structure used to store either partially sent data or partially received
 * data.
 */
struct rw_cache
{
  uint8_t *data; //!< Data area.
  size_t len; //!< How much is read or how much is left to send.
};

struct sukat_sock_client_ctx
{
  int fd; //!< Accepted fd.
  void *client_caller_ctx; //!< Specific context if set. Otherwise NULL.
  struct {
      uint8_t destroyed:1; //!< If true, destroy on first chance.
      uint8_t epollout:1; //!< If true, we're also waiting for epollout.
      uint8_t closed:1; //!< True if client already closed
      uint8_t unused:5;
  };
  sukat_sock_t *main_ctx; //!< Backwards pointer to sukat_sock_t.
  struct rw_cache read_cache;
  struct rw_cache write_cache;
  sukat_sock_client_t *next; //!< Next pointer if in deleted list.
};

struct sukat_sock_ctx
{
  struct sukat_sock_cbs cbs;
  int fd; //!< Main fd for accept to server or connected fd for client.
  void *caller_ctx; //!< If true, dont delete immediately.
  int epoll_fd;
  struct {
      uint8_t connect_in_progress:1; //! If set, a connect returned EINPROCESS
      uint8_t is_server:1; //!< True for server operation.
      uint8_t in_callback:1; //!< If true, don't destroy oneself immediately.
      uint8_t destroyed:1; //!< If true, don't destroy oneself immediately.
      uint8_t epollout:1; //!< If true, we're also waiting for epollout.
  };
  size_t n_connections;
  int master_epoll_fd;
  int domain;
  int type;
  union
    {
      struct sockaddr_storage storage;
      struct sockaddr_in sin;
      struct sockaddr_in6 sin6;
      struct sockaddr_un sun;
      struct sockaddr_tipc stipc;
      struct sockaddr saddr;
    };
  socklen_t slen;
  union {
      struct {
          struct rw_cache read_cache;
          struct rw_cache write_cache;
      };
      struct {
          sukat_sock_client_t *deleted_head;
          sukat_sock_client_t *deleted_tail;
      };
  };
};

#define USE_CB(_ctx, _cb, ...)                                                \
  do                                                                          \
    {                                                                         \
      if (_ctx && _ctx->cbs._cb)                                              \
        {                                                                     \
          bool old_value = _ctx->in_callback;                                 \
                                                                              \
          _ctx->in_callback = true;                                           \
          _ctx->cbs._cb(__VA_ARGS__);                                         \
          _ctx->in_callback = old_value;                                      \
        }                                                                     \
    }                                                                         \
  while (0)

#define USE_CB_WRET(_ctx, _ret, _cb, ...)                                     \
  do                                                                          \
    {                                                                         \
      if (_ctx && _ctx->cbs._cb)                                              \
        {                                                                     \
          bool old_value = _ctx->in_callback;                                 \
                                                                              \
          _ctx->in_callback = true;                                           \
          _ret = _ctx->cbs._cb(__VA_ARGS__);                                  \
          _ctx->in_callback = old_value;                                      \
        }                                                                     \
    }                                                                         \
  while (0)

static bool socket_connection_oriented(int type)
{
  if (type == SOCK_DGRAM || type == SOCK_RDM)
    {
      return false;
    }
  return true;
}

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

static char *socket_log(sukat_sock_t *ctx, struct sukat_sock_params *params,
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
      SAFEPUT("Unknown %d", domain);
      break;
    }

  return buf;
}

static char *socket_log_saddr(sukat_sock_t *ctx, char *buf, size_t buf_len)
{
  size_t n_used = 0;
  char inet_buf[INET6_ADDRSTRLEN];

  assert(ctx != NULL && buf != NULL && buf_len > 0);
  switch(ctx->type)
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
      SAFEPUT("Unknown type %d", ctx->type);
      break;
    }

  switch(ctx->domain)
    {
    case AF_UNIX:
      SAFEPUT("UNIX %s", ctx->sun.sun_path);
    case AF_TIPC:
      SAFEPUT("TIPC port_type %u instance %u", ctx->stipc.addr.nameseq.type,
              ctx->stipc.addr.nameseq.lower);
    case AF_INET:
    case AF_INET6:
      SAFEPUT("IPv%d IP %s port %hu", (ctx->domain == AF_INET) ? 4 : 6,
              inet_ntop(ctx->domain, (ctx->domain == AF_INET) ?
                        (void *)&ctx->sin.sin_addr :
                        (void *)&ctx->sin6.sin6_addr,
                        inet_buf, sizeof(inet_buf)),
              ntohs(ctx->sin.sin_port));
      // I don't think AF_UNSPEC should be here anymore
       break;
    default:
      SAFEPUT("Unknown family %d", ctx->domain);
      break;
    }
  return buf;
}

#undef SAFEPUT

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

#define RW_CACHE(_ptr, _write)                                                \
  ((write) ? &_ptr->write_cache : &_ptr->read_cache)

static bool cache(sukat_sock_t *ctx, sukat_sock_client_t *client,
                  uint8_t *buf, size_t buf_amount, bool write)
{
  bool ret;

  assert(ctx != NULL && buf != NULL);
  if(!buf_amount)
    {
      return true;
    }
  DBG(ctx, "Caching %zu bytes from %s to %s", buf_amount,
      (write) ? "writing" : "reading", (client) ? "client" : "main");
  if (client)
    {
      ret = cache_to(RW_CACHE(client, write), buf, buf_amount);
    }
  else
    {
      ret = cache_to(RW_CACHE(ctx, write), buf, buf_amount);
    }
  if (ret == false)
    {
      ERR(ctx, "Cannot cache %zu bytes for %s data: %s", buf_amount,
          (write) ? "write" : "read", strerror(errno));
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

static void uncache(sukat_sock_t *ctx, sukat_sock_client_t *client,
                    uint8_t *buf, size_t *uncached, bool write)
{
  assert(ctx != NULL && buf != NULL && uncached != NULL);
  if (client)
    {
      uncache_from(RW_CACHE(client, write), buf, uncached);
    }
  else
    {
      uncache_from(RW_CACHE(ctx, write), buf, uncached);
    }
}

/*!
 * Set O_CLOEXEC and O_NONBLOCK
 */
static bool set_flags(sukat_sock_t *ctx, int fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0)
    {
      flags |= O_NONBLOCK;
      if (fcntl(fd, F_SETFL, flags) == 0)
        {
          flags = fcntl(fd, F_GETFD, 0);
          if (flags >= 0)
            {
              flags |= FD_CLOEXEC;
              if (fcntl(fd, F_SETFD, flags) == 0)
                {
                  return true;
                }
            }
        }
    }
  ERR(ctx, "Failed to set flags to fd %d: %s", fd, strerror(errno));
  return false;
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

static bool socket_fill_unix(sukat_sock_t *ctx,
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

static int socket_create_hinted(sukat_sock_t *ctx, struct addrinfo *p,
                                bool server, int backlog)
{
  int fd = socket(p->ai_family, p->ai_socktype |
                  SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      ERR(ctx, "Failed to create socket: %s", strerror(errno));
      return -1;
    }
  if (server)
    {
      int enable = 1;

      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                     &enable, sizeof(int)) != 0)
        {
          ERR(ctx, "Failed to set SO_REUSEADDR to socket %d: %s",
              fd, strerror(errno));
          close(fd);
          return -1;
        }

      if (bind(fd, p->ai_addr, p->ai_addrlen) != 0)
        {
          ERR(ctx, "Failed to bind to socket: %s", strerror(errno));
          goto fail;
        }
      if (socket_connection_oriented(p->ai_socktype) == true)
        {
          if (backlog == 0)
            {
              backlog = SOMAXCONN;
            }
          if (listen(fd, backlog) != 0)
            {
              ERR(ctx, "Failed to listen to socket: %s", strerror(errno));
              goto fail;
            }
        }
    }
  else
    {
      if (connect(fd, p->ai_addr, p->ai_addrlen) != 0)
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
  return fd;
fail:
  close(fd);
  return -1;
}

static bool is_inet(int domain)
{
  if (domain == AF_INET || domain == AF_INET6 || domain == AF_UNSPEC)
    {
      return true;
    }
  return false;
}

/*!
 * Socket creation for client server and any domain/type. Adapted from Beejs
 * of course.
 *
 * @param ctx           Main context.
 * @param params        Parameters for socket.
 *
 * @return >= 0         Valid fd.
 * @return < 0          Failure.
 * */
static int socket_create(sukat_sock_t *ctx, struct sukat_sock_params *params)
{
  int main_fd = -1;
  char socket_buf[128];
  union {
      struct sockaddr_un sun;
      struct sockaddr_tipc tipc;
  } socks;
  struct addrinfo hints = { }, *servinfo = NULL, *p;

  memset(&socks, 0, sizeof(socks));
  LOG(ctx, "%s: Creating", socket_log(ctx, params, socket_buf,
                                      sizeof(socket_buf)));
  p = &hints;
  hints.ai_family = params->domain;
  hints.ai_socktype = params->type;
  hints.ai_addr = (struct sockaddr *)&socks;

  if (params->domain == AF_UNIX)
    {
      if (socket_fill_unix(ctx, params, &socks.sun, &hints.ai_addrlen) != true)
        {
          return -1;
        }
    }
  else if (params->domain == AF_TIPC)
    {
      socket_fill_tipc(params, &socks.tipc, &hints.ai_addrlen);
    }
  else if (is_inet(params->domain))
    {
      hints.ai_addr = NULL;
      hints.ai_flags = AI_PASSIVE;
      if (getaddrinfo(params->pinet.ip, params->pinet.port, &hints, &servinfo)
          != 0)
        {
          ERR(ctx, "Failed to getaddrinfo for %s:%s", params->pinet.ip,
              params->pinet.port);
          return -1;
        }
      p = servinfo;
    }
  else
    {
      ERR(ctx, "domain %d socket not implemented", params->domain);
      return -1;
    }

  for (;p && main_fd == -1 ; p = p->ai_next)
    {
      main_fd = socket_create_hinted(ctx, p, params->server, params->listen);
      if (main_fd >= 0)
        {
          ctx->slen = p->ai_addrlen;

          /* In the server case we might use port so add extra querying for
             these scenarios */
          if (ctx->is_server && is_inet(params->domain))
            {
              ctx->slen = sizeof(ctx->storage);
              if (getsockname(main_fd, &ctx->saddr, &ctx->slen) != 0)
                {
                  ERR(ctx, "Failed to query address server is bound to :%s",
                      strerror(errno));
                  close(main_fd);
                  continue;
                }
            }
          else
            {
              memcpy(&ctx->sin, p->ai_addr, p->ai_addrlen);
            }
          ctx->n_connections++;
          ctx->domain = p->ai_family;
          ctx->type = p->ai_socktype;

          LOG(ctx, "%s created", socket_log_saddr(ctx, socket_buf,
                                                  sizeof(socket_buf)));
          break;
        }
    }
  if (servinfo)
    {
      freeaddrinfo(servinfo);
    }

  return main_fd;
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

static bool event_add_to_ctx(sukat_sock_t *ctx, int fd, void *data, int op,
                             uint32_t events) {
    if (event_ctl(ctx->epoll_fd, fd, data, op, events) != true)
      {
        ERR(ctx, "Failed to add fd %d events %u: %s", fd, events,
            strerror(errno));
        return false;
      }
    return true;
}

static bool event_epollout(sukat_sock_t *ctx,
                           sukat_sock_client_t *client, bool end)
{
  void *data = (client) ? (void *)client : (void *)ctx;
  int fd = (client) ? client->fd : ctx->fd;
  bool epollout_flag = (client) ? client->epollout : ctx->epollout;
  uint32_t events = EPOLLIN;

  if (!end)
    {
      events |= EPOLLOUT;
    }

  if (!(epollout_flag ^ end))
    {
      if (event_add_to_ctx(ctx, fd, data, EPOLL_CTL_MOD, events) != true)
        {
          return false;
        }
      if (client)
        {
          client->epollout = (end) ? 0 : 1;
        }
      else
        {
          ctx->epollout = (end) ? 0 : 1;
        }
    }
  return true;
}

static void *get_caller_ctx(sukat_sock_t *ctx, sukat_sock_client_t *client)
{
  if (client && client->client_caller_ctx)
    {
      return client->client_caller_ctx;
    }
  return ctx->caller_ctx;
}

static void client_close(sukat_sock_t *ctx, sukat_sock_client_t *client)
{
  uint32_t events = EPOLLIN;
  void *caller_ctx = get_caller_ctx(ctx, client);

  if (client->closed)
    {
      return;
    }
  LOG(ctx, "Removing client %d", client->fd);
  if (client->epollout)
    {
      events |= EPOLLOUT;
    }
  event_ctl(ctx->epoll_fd, client->fd, NULL, EPOLL_CTL_DEL, events);
  free_cache(&client->read_cache);
  free_cache(&client->write_cache);
  close(client->fd);
  if (!client->destroyed)
    {
      USE_CB(ctx, conn_cb, caller_ctx, client, NULL, 0, true);
    }
  ctx->n_connections--;
  if (!ctx->in_callback)
    {
      free(client);
    }
  else
    {
      client->closed = true;
      if (!ctx->deleted_tail)
        {
          assert(!ctx->deleted_head);
          ctx->deleted_head = ctx->deleted_tail = client;
        }
      else
        {
          ctx->deleted_tail->next = client;
          ctx->deleted_tail = client;
        }
    }
}

typedef enum event_handling_ret
{
  ERR_FATAL = -1,
  ERR_OK = 0,
  ERR_BREAK = 1,
} ret_t;

static bool ret_was_ok(sukat_sock_t *ctx, sukat_sock_client_t *client,
                       ssize_t ret)
{
  if (ret <= 0)
    {
      if (!(ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)))
        {
          int client_id = (client) ? client->fd : 0;
          void *caller_ctx = get_caller_ctx(ctx, client);

          ERR(ctx, "Connection %s%s", (ret == 0) ? "closed" :
              "severed: ", (ret == -1) ? strerror(errno) : "");
          USE_CB(ctx, error_cb, caller_ctx, client_id, errno);
          return false;
        }
    }
  return true;
}

/*!
 * Accept client connections until blocked
 *
 * @param ctx   Sukat context.
 *
 * @return ERR_OK    Success.
 * @return ERR_FATAL Fatal error.
 */
static ret_t server_accept_cb(sukat_sock_t *ctx)
{
  struct sockaddr_storage saddr;
  socklen_t slen = sizeof(saddr);
  int fd;

  while (ctx->destroyed != true &&
         (fd = accept(ctx->fd, (struct sockaddr *)&saddr, &slen)) >= 0)
    {
      if (set_flags(ctx, fd) == true)
        {
          sukat_sock_client_t *client =
            (sukat_sock_client_t *)calloc(1, sizeof(*client));

          if (client)
            {
              client->fd = fd;
              client->main_ctx = ctx;

              if (event_add_to_ctx(ctx, fd, client, EPOLL_CTL_ADD,
                                   EPOLLIN) == true)
                {
                  LOG(ctx, "New client with fd %d", fd);
                  ctx->n_connections++;
                  USE_CB_WRET(ctx, client->client_caller_ctx, conn_cb,
                              ctx->caller_ctx, client, &saddr, slen, false);
                  continue;
                }
              free(client);
            }
        }
      close(fd);
    }
  if (ret_was_ok(ctx, NULL, fd) == false)
    {
      ERR(ctx, "Failed to accept: %s", strerror(errno));
      return ERR_FATAL;
    }
  return ERR_BREAK;
}

static ret_t client_continue_connect(sukat_sock_t *ctx)
{
  int opt;
  socklen_t len = sizeof(opt);

  if (getsockopt(ctx->fd, SOL_SOCKET, SO_ERROR, &opt, &len) == 0)
    {
      if (!opt)
        {
          LOG(ctx, "Connected!");
          ctx->connect_in_progress = false;
          event_epollout(ctx, NULL, true);
          USE_CB(ctx, conn_cb, ctx->caller_ctx, NULL, &(ctx->storage),
                 ctx->slen, false);
          return ERR_OK;
        }
      else
        {
          ERR(ctx, "Connect failed: %s", strerror(opt));
        }
    }
  else
    {
      ERR(ctx, "Failed to query connection state: %s", strerror(errno));
    }
  return ERR_FATAL;
}

static bool keep_going(sukat_sock_t *ctx,
                       sukat_sock_client_t *client)
{
  if (ctx->destroyed || (client && client->destroyed))
    {
      return false;
    }
  return true;
}

#define BUF_LEFT (sizeof(buf) - n_read)
#define UNPROCESSED (n_read - processed)
#define ITBLOCKS(_retval)                                                     \
  (_retval == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))

static ret_t read_stream(sukat_sock_t *ctx, sukat_sock_client_t *client)
{
  uint8_t buf[BUFSIZ];
  ssize_t read_now;
  bool blocked = false;
  size_t n_read = 0;

  DBG(ctx, "Reading from %s", (client) ? "client" : "server");

  uncache(ctx, client, buf, &n_read, false);

  while (blocked == false)
    {
      int fd = (client) ? client->fd : ctx->fd;
      size_t processed;
      void *caller_ctx = get_caller_ctx(ctx, client);
      int client_id = (client) ? client->fd : 0;

      do
        {
          read_now = read(fd, buf + n_read, BUF_LEFT);
        } while (read_now > 0 && (n_read += read_now) < sizeof(buf));
      if (ret_was_ok(ctx, client, read_now) != true)
        {
          return ERR_FATAL;
        }
      else if (ITBLOCKS(read_now))
        {
          blocked = true;
        }

      DBG(ctx, "Read %zu bytes from %s", n_read, (client) ? "client" :
          "server");

      processed = 0;
      while (UNPROCESSED && keep_going(ctx, client))
        {
          size_t msg_len = 0;

          if (ctx->cbs.msg_len_cb)
            {
              int msg_len_query;

              USE_CB_WRET(ctx, msg_len_query, msg_len_cb, caller_ctx,
                          buf + processed, UNPROCESSED);
              if (ctx->destroyed || (client && client->destroyed))
                {
                  return ERR_OK;
                }
              if (msg_len_query < 0)
                {
                  ERR(ctx, "Corruption detected by caller");
                  return ERR_FATAL;
                }
              msg_len = (size_t)msg_len_query;
              if ((msg_len == 0 || msg_len > UNPROCESSED))
                {
                  if (blocked != true)
                    {
                      memmove(buf, buf + processed, UNPROCESSED);
                      break;
                    }
                  else
                    {
                      if (cache(ctx, client, buf + processed,
                                UNPROCESSED, false) != true)
                        {
                          USE_CB(ctx, error_cb,
                                 caller_ctx, client_id, ENOMEM);
                          return ERR_FATAL;
                        }
                      return ERR_OK;
                    }
                }
            }
          else
            {
              ERR(ctx, "Stream oriented without a msg_len_cb not implemented");
              return ERR_FATAL;
            }
          USE_CB(ctx, msg_cb,
                 caller_ctx, client, buf + processed, msg_len);
          processed += msg_len;
        }
      if (processed == n_read)
        {
          n_read = 0;
        }
      else
        {
          n_read = UNPROCESSED;
        }
    }

  return ERR_OK;
}

static void clients_free_deleted(sukat_sock_t *ctx)
{
  assert(ctx != NULL);
  if (!ctx->is_server)
    {
      return;
    }
  while (ctx->deleted_head)
    {
      sukat_sock_client_t *client = ctx->deleted_head;

      ctx->deleted_head = client->next;
      free(client);
    }
  ctx->deleted_head = ctx->deleted_tail = NULL;
}

static ret_t read_seqpacket(sukat_sock_t *ctx, sukat_sock_client_t *client)
{
  ERR(ctx, "Not implemented");
  (void)client;
  return ERR_FATAL;
}

static ret_t read_connectionless(sukat_sock_t *ctx,
                                 sukat_sock_client_t *client)
{
  ERR(ctx, "Not implemented");
  (void)client;
  return ERR_FATAL;
}

/*!
 * Send any cached data. Should only happen on connection oriented sockets
 *
 * @param ctx Main context.
 * @param client If non-null, client context. If NULL we're using socket in
 *        main.
 */
static enum sukat_sock_send_return
send_cached(sukat_sock_t *ctx, sukat_sock_client_t *client)
{
  struct rw_cache *cache = (client) ? &client->write_cache : &ctx->write_cache;

  if (cache->data && cache->len)
    {
      size_t sent = 0;
      ssize_t ret;
      int fd = (client) ? client->fd : ctx->fd;

      DBG(ctx, "Finishing send of %zu bytes to %s.", cache->len,
          (client) ? "client" :"server");

      do
        {
          ret = write(fd, cache->data + sent, cache->len - sent);
        } while (ret > 0 && (sent  += ret) < cache->len);
      if (ret_was_ok(ctx, client, ret) != true)
        {
          return SUKAT_SEND_ERROR;
        }
      if (sent == cache->len)
        {
          free_cache(cache);
          if (event_epollout(ctx, client, true) != true)
            {
              return SUKAT_SEND_ERROR;
            }
          /* Stop waiting for EPOLLOUT */
        }
      else
        {
          /* If we sent 0, we don't need to do anyting, just try again. */
          if (sent != 0)
            {
              size_t left = cache->len - sent;
              uint8_t *data = (uint8_t *)malloc(left);
              DBG(ctx, "Still missing %zu bytes to send", left);

              if (!data)
                {
                  ERR(ctx, "Could not cache data for sending: %s", strerror);
                  return SUKAT_SEND_ERROR;
                }
              memcpy(data, cache->data + sent, left);
              free_cache(cache);
              cache->data = data;
              cache->len = left;
            }
          return SUKAT_SEND_EAGAIN;
        }
    }
  return SUKAT_SEND_OK;
}

static ret_t event_read(sukat_sock_t *ctx,
                        sukat_sock_client_t *client)
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

static void event_non_epollin(sukat_sock_t *ctx,
                              sukat_sock_client_t *client, uint32_t events)
{
  void *caller_ctx = get_caller_ctx(ctx, client);
  int errval = (events & EPOLLHUP) ? ECONNABORTED :
    ECONNRESET;

  ERR(ctx, "%s event received from %s connection",
      (events == EPOLLERR) ? "Error" : "Disconnect",
      (client) ? "client" : "main");
  USE_CB(ctx, error_cb, caller_ctx, -1, errval);
}

static ret_t event_handle(sukat_sock_t *ctx, struct epoll_event *event)
{
  ret_t ret = ERR_OK;

  if (event->data.ptr == (void *)ctx)
    {
      if (event->events != EPOLLIN && event->events != EPOLLOUT)
        {
          event_non_epollin(ctx, NULL, event->events);
          return ERR_FATAL;
        }
      else if (!ctx->is_server && ctx->connect_in_progress)
        {
          ret = client_continue_connect(ctx);
        }
      else if (ctx->is_server)
        {
          ret = server_accept_cb(ctx);
        }
      else
        {
          if (event->events == EPOLLOUT && ctx->write_cache.len > 0)
            {
              if (send_cached(ctx, NULL) != SUKAT_SEND_OK)
                {
                  return ERR_BREAK;
                }
            }
          else
            {
              return event_read(ctx, NULL);
            }
        }
    }
  else
  {
    sukat_sock_client_t *client = (sukat_sock_client_t *)(event->data.ptr);

      if (!client->closed)
        {
          if (event->events != EPOLLIN && event->events != EPOLLOUT)
            {
              event_non_epollin(ctx, client, event->events);
              client_close(ctx, client);
            }
          else
            {
              if (event->events == EPOLLOUT)
                {
                  if (client->write_cache.len == 0)
                    {
                      ERR(ctx, "Epollout set although nothing to send");
                    }
                  else
                    {
                      if (send_cached(ctx, client) == SUKAT_SEND_ERROR)
                        {
                          client_close(ctx, client);
                        }
                    }
                }
              else
                {
                  ret = event_read(ctx, client);

                  if (ret != ERR_OK || client->destroyed)
                    {
                      client_close(ctx, client);
                    }
                }
            }
        }
    }

  return ret;
}

/* TODO: Not sure if events can be other than EPOLLIN if the slave
 * fds have other than EPOLLIN */
int sukat_sock_read(sukat_sock_t *ctx, int timeout)
{
  int nfds;
  ret_t ret = ERR_OK;

  if (!ctx)
    {
      errno = EINVAL;
      return -1;
    }
  do
    {
      ret = ERR_OK;
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
      for (i = 0; i < (size_t)nfds && ret == ERR_OK ; i++)
        {
          ctx->in_callback = true;
          ret = event_handle(ctx, &new_events[i]);
          ctx->in_callback = false;
        }
      if (timeout > 0)
        {
          timeout = 0;
        }
    } while (nfds > 0 && ctx->destroyed != true && ctx->n_connections > 0 &&
             ret != ERR_FATAL);

out:
  if (ret == ERR_BREAK)
    {
      ret = ERR_OK;
    }
  if (ctx->destroyed)
    {
      sukat_sock_destroy(ctx);
    }
  else
    {
      clients_free_deleted(ctx);
    }
  return (int)ret;
}

sukat_sock_t *sukat_sock_create(struct sukat_sock_params *params,
                                struct sukat_sock_cbs *cbs)
{
  sukat_sock_t *ctx;

  if (!params)
    {
      if (cbs && cbs->log_cb)
        {
          cbs->log_cb(SUKAT_LOG_ERROR, "No parameters given");
        }
      return NULL;
    }

  ctx = (sukat_sock_t *)calloc(1, sizeof(*ctx));
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
  if (!ctx->is_server)
    {
      if (ctx->connect_in_progress)
        {
          event_epollout(ctx, NULL, false);
        }
      else if (socket_connection_oriented(ctx->type))
        {
          ctx->in_callback = true;
          USE_CB(ctx, conn_cb,
                 ctx->caller_ctx, NULL, &ctx->storage, ctx->slen, false);
          ctx->in_callback = false;
          if (ctx->destroyed)
            {
              goto fail;
            }
        }
    }

  return ctx;

fail:
  sukat_sock_destroy(ctx);
  return NULL;
}

void sukat_sock_destroy(sukat_sock_t *ctx)
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
          ctx->n_connections--;
        }
      if (ctx->master_epoll_fd != -1)
        {
          if (event_ctl(ctx->master_epoll_fd, ctx->epoll_fd, ctx, EPOLL_CTL_DEL,
                        EPOLLIN) != true) {
              ERR(ctx, "Failed to remove epoll_fd from master fd: %s",
                  strerror(errno));
          }
        }
      if (ctx->epoll_fd > 0)
        {
          close(ctx->epoll_fd);
        }
      free_cache(&ctx->read_cache);
      free_cache(&ctx->write_cache);
      clients_free_deleted(ctx);
      free(ctx);
    }
}

int sukat_sock_get_epoll_fd(sukat_sock_t *ctx)
{
  if (ctx)
    {
      return ctx->epoll_fd;
    }
  errno = EINVAL;
  return -1;
}

static enum sukat_sock_send_return send_stream_msg(sukat_sock_t *ctx,
                                                   sukat_sock_client_t *client,
                                                   uint8_t *msg, size_t msg_len)
{
  ssize_t ret;
  size_t sent = 0;
  int fd = (client) ? client->fd : ctx->fd;

  DBG(ctx, "Sending %zu bytes of stream to %s", msg_len,
      (client) ? "client" : "server");

  do
    {
      ret = write(fd, msg + sent, msg_len - sent);
    }
  while (ret > 0 && (sent += ret) < msg_len);
  if (ret_was_ok(ctx, client, ret) == true)
    {
      /* If we cant send a single byte, just return EAGAIN */
      if (sent == 0)
        {
          return SUKAT_SEND_EAGAIN;
        }
      if (cache(ctx, client, msg + sent, msg_len - sent, true) == true)
        {
          if ((msg_len == sent) || event_epollout(ctx, client, false) == true)
            {
              return SUKAT_SEND_OK;
            }
        }
    }
  return SUKAT_SEND_ERROR;
}

static enum sukat_sock_send_return send_dgram_msg(sukat_sock_t *ctx,
                                                  sukat_sock_client_t *client,
                                                  uint8_t *msg, size_t msg_len)
{
  //TODO.
  (void)ctx;
  (void)client;
  (void)msg;
  (void)msg_len;
  return SUKAT_SEND_ERROR;
}

static enum sukat_sock_send_return send_seqm_msg(sukat_sock_t *ctx,
                                                 sukat_sock_client_t *client,
                                                 uint8_t *msg, size_t msg_len)
{
  //TODO.
  (void)ctx;
  (void)client;
  (void)msg;
  (void)msg_len;
  return SUKAT_SEND_ERROR;
}

enum sukat_sock_send_return sukat_send_msg(sukat_sock_t *ctx,
                                           sukat_sock_client_t *client,
                                           uint8_t *msg, size_t msg_len)
{
  enum sukat_sock_send_return ret = SUKAT_SEND_OK;

  if (!ctx)
    {
      return SUKAT_SEND_ERROR;
    }
  if (ctx->connect_in_progress)
    {
      ERR(ctx, "Cannot send message, since connect still in progress");
      errno = EINPROGRESS;
      return SUKAT_SEND_ERROR;
    }

  ret = send_cached(ctx, client);
  if (ret != SUKAT_SEND_OK)
    {
      return ret;
    }
  if (socket_connection_oriented(ctx->type))
    {
      if (ctx->type == SOCK_STREAM)
        {
          return send_stream_msg(ctx, client, msg, msg_len);
        }
      return send_seqm_msg(ctx, client, msg, msg_len);
    }
  return send_dgram_msg(ctx, client, msg, msg_len);
}

void sukat_sock_disconnect(sukat_sock_t *ctx, sukat_sock_client_t *client)
{
  if (ctx != NULL && client != NULL)
    {
      client->destroyed = true;
      client_close(ctx, client);
    }
}

/*! }@ */
