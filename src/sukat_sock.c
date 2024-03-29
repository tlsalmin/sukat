/*!
 * @file sukat_sock.c
 * @brief Implentation of sukat socket API.
 *
 * @addtogroup sukat_sock
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
#include <limits.h>
#include <sys/un.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "sukat_util.h"
#include "sukat_sock.h"
#include "sukat_log_internal.h"
#include "sukat_drawer.h"
#include "delayed_destruction.h"

/*!
 * Structure used to store either partially sent data or partially received
 * data.
 */
struct rw_cache
{
  uint8_t *data; //!< Data area.
  size_t len; //!< How much is read or how much is left to send.
};

struct fd_info
{
  int fd; //!< Main fd for accept/read for server.
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
  int type;
};

struct sukat_sock_endpoint_ctx
{
  destro_client_t destro_client_ctx;
  void *endpoint_caller_ctx; //!< Specific context if set. Otherwise NULL.
  struct {
      uint8_t destroyed:1; //!< If true, destroy on first chance.
      uint8_t epollout:1; //!< If true, we're also waiting for epollout.
      uint8_t closed:1; //!< True if peer already closed
      uint8_t connect_in_progress:1; //!< Connect not yet completed.
      uint8_t is_server:1; //!< True if this is a server socket.
      uint8_t stack_dummy:1; //!< Stack allocated dummy in connectionless read.
      uint8_t unused:2;
  };
  struct fd_info info;
  struct rw_cache read_cache;
  struct rw_cache write_cache;
};

struct sukat_sock_ctx
{
  struct sukat_sock_cbs cbs;
  void *caller_ctx; //!< If connection specific context not specied, use this.
  int epoll_fd;
  size_t n_connections;
  size_t max_packet_size;
  int master_epoll_fd;
  destro_t *destro_ctx;
};

#define USE_CB(_ctx, _cb, ...)                                                \
  do                                                                          \
    {                                                                         \
      if (_ctx && _ctx->cbs._cb)                                              \
        {                                                                     \
          _ctx->cbs._cb(__VA_ARGS__);                                         \
        }                                                                     \
    }                                                                         \
  while (0)

#define USE_CB_WRET(_ctx, _ret, _cb, ...)                                     \
  do                                                                          \
    {                                                                         \
      if (_ctx && _ctx->cbs._cb)                                              \
        {                                                                     \
          _ret = _ctx->cbs._cb(__VA_ARGS__);                                  \
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

static size_t sock_log_type(int type, char *buf, size_t buf_len)
{
  size_t ret;

  switch(type)
    {
    case SOCK_STREAM:
      ret = snprintf(buf, buf_len, "Stream ");
      break;
    case SOCK_DGRAM:
      ret = snprintf(buf, buf_len, "Datagram ");
      break;
    case SOCK_SEQPACKET:
      ret = snprintf(buf, buf_len, "Seqpacket ");
      break;
    default:
      ret = snprintf(buf, buf_len, "Unknown type %d ", type);
      break;
    }

  return ret;
}

static char *socket_log_params(struct sukat_sock_endpoint_params *params,
                               char *buf, size_t buf_len)
{
  size_t n_used = 0;

  assert(buf != NULL && buf_len > 0 && params != NULL);

  n_used += sock_log_type(params->type, buf, buf_len);

  SAFEPUT((params->server) ? "server ": "client ");
  switch (params->domain)
    {
    case AF_UNIX:
      SAFEPUT("UNIX %s%s", (params->punix.is_abstract) ? "abstract " :
              "", params->punix.name);
      break;
    case AF_TIPC:
      SAFEPUT("TIPC type %d service %d", params->ptipc.port_type,
              params->ptipc.port_instance);
      break;
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      SAFEPUT("INET %s:%s", params->pinet.ip, params->pinet.port);
      break;
    default:
      SAFEPUT("Unknown %d", params->domain);
      break;
    }

  return buf;
}

static char *sock_log_saddr(struct sockaddr_storage *saddr, char *buf,
                            size_t buf_len)
{
  int domain;
  union {
      struct sockaddr_un *sun;
      struct sockaddr_in *sin;
      struct sockaddr_in6 *sin6;
      struct sockaddr_storage *storage;
      struct sockaddr_tipc *stipc;
  } info;
  size_t n_used = 0;
  char inet_buf[INET6_ADDRSTRLEN];

  info.storage = saddr;
  domain = info.storage->ss_family;

  switch (domain)
    {
      case AF_UNIX:
        snprintf(buf, buf_len, "%sUNIX %s",
                 (info.sun->sun_path[0] == '\0') ? "Abstract " : "",
                 (info.sun->sun_path[0] == '\0') ? info.sun->sun_path + 1
                                                 : info.sun->sun_path);
        break;
      case AF_TIPC:
        snprintf(buf, buf_len, "TIPC port_type %u instance %u",
                 ntohl(info.stipc->addr.nameseq.type),
                 ntohl(info.stipc->addr.nameseq.lower));
        break;
      case AF_INET:
      case AF_INET6:
        snprintf(buf, buf_len, "IPv%d IP %s port %hu",
                 (domain == AF_INET) ? 4 : 6,
                 inet_ntop(domain,
                           (domain == AF_INET) ? (void *)&info.sin->sin_addr
                                               : (void *)&info.sin6->sin6_addr,
                           inet_buf, sizeof(inet_buf)),
                 ntohs(info.sin->sin_port));
        // I don't think AF_UNSPEC should be here anymore
        break;
      default:
        SAFEPUT("Unknown family %d", domain);
        break;
    }
  return buf;
}

static char *socket_log_fd_info(struct fd_info *info, char *buf, size_t buf_len)
{
  size_t n_used = 0;

  assert(info != NULL && buf != NULL && buf_len > 0);

  n_used += sock_log_type(info->type, buf, buf_len);

  if (buf_len > n_used)
    {
      sock_log_saddr(&info->storage, buf + n_used, buf_len - n_used);
    }
  return buf;
}

char *sukat_sock_endpoint_to_str(sukat_sock_endpoint_t *endpoint, char *buf,
                                 const size_t buf_len)
{
  if (endpoint && buf && buf_len)
    {
      return socket_log_fd_info(&endpoint->info, buf, buf_len);
    }
  return NULL;
}

#undef SAFEPUT

char *fd_to_str(int fd, char *buf, size_t buf_len)
{
  struct sockaddr_storage saddr;
  socklen_t slen = sizeof(saddr);

  if (!getsockname(fd, (struct sockaddr *)&saddr, &slen))
    {
      char src[255];

      sock_log_saddr(&saddr, src, sizeof(src));
      slen = sizeof(saddr);

      memset(&saddr, 0, sizeof(saddr));
      if (!getpeername(fd, (struct sockaddr *)&saddr, &slen))
        {
          char dst[255];
          sock_log_saddr(&saddr, dst, sizeof(dst));
          snprintf(buf, buf_len, "%s-%s", src, dst);
        }
      else
        {
          snprintf(buf, buf_len, "%s-unconnected", src);
        }
    }
  else
    {
      snprintf(buf, buf_len, "%s", strerror(errno));
    }
  return buf;
}

char *sukat_sock_endpoint_fd_to_str(sukat_sock_endpoint_t *endpoint, char *buf,
                                    size_t buf_len)
{
  return fd_to_str(endpoint->info.fd, buf, buf_len);
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

#define RW_CACHE(_ptr, _write)                                                \
  ((write) ? &_ptr->write_cache : &_ptr->read_cache)

static bool cache(sukat_sock_t *ctx, sukat_sock_endpoint_t *peer,
                  uint8_t *buf, size_t buf_amount, bool write)
{
  bool ret;

  assert(ctx != NULL && buf != NULL && peer != NULL);
  if(!buf_amount)
    {
      return true;
    }
  DBG(ctx, "Caching %zu bytes from %s", buf_amount,
      (write) ? "writing" : "reading");
  ret = cache_to(RW_CACHE(peer, write), buf, buf_amount);
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

static void uncache(__attribute__((unused)) sukat_sock_t *ctx,
                    sukat_sock_endpoint_t *peer,
                    uint8_t *buf, size_t *uncached, bool write)
{
  assert(ctx != NULL && buf != NULL && uncached != NULL && peer != NULL);
  uncache_from(RW_CACHE(peer, write), buf, uncached);
}

/*!
 * Set O_CLOEXEC and O_NONBLOCK
 */
static bool set_flags(sukat_sock_t *ctx, int fd)
{
  if (!sukat_util_flagit(fd))
    {
      return true;
    }
  ERR(ctx, "Failed to set flags to fd %d: %s", fd, strerror(errno));
  return false;
}

static void socket_fill_tipc(struct sukat_sock_endpoint_params *params,
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
                             struct sukat_sock_endpoint_params *params,
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
      n_used++;
    }
  snprintf(sun->sun_path + n_used, sizeof(sun->sun_path) -
           n_used - 1, "%s", params->punix.name);
  *addrlen = sizeof(*sun);

  return true;
}

static bool prebind(sukat_sock_t *ctx, int fd, int family,
                    const struct sukat_sock_endpoint_params *params)
{
  struct sockaddr_storage saddr = { };
  socklen_t slen = sizeof(saddr);

  assert(fd != -1);
  saddr.ss_family = family;

  switch (family)
    {
      case AF_INET:
      case AF_INET6:
        if (inet_pton(family, params->source.pinet.ip,
                      (family == AF_INET6
                         ? (struct sockaddr *)&((struct sockaddr_in6 *)&saddr)
                             ->sin6_addr
                         : (struct sockaddr *)&((struct sockaddr_in *)&saddr)
                             ->sin_addr)) != 1)
          {
            ERR(ctx, "Failed to convert %s to binary address of family %d: %m",
                params->source.pinet.ip, family);
            return false;
          }
        slen = (family == AF_INET ? sizeof(struct sockaddr_in)
                                  : sizeof(struct sockaddr_in6));
        break;
      default:
        LOG(ctx, "Unimplemented prebinding for family %d", family);
        return true;
        break;
    }
  if (!bind(fd, (struct sockaddr *)&saddr, slen))
    {
      slen = sizeof(saddr);

      if (!getsockname(fd, (struct sockaddr *)&saddr, &slen))
        {
          char ipstr[INET6_ADDRSTRLEN];

          LOG(ctx, "Prebound %d to %s(orig %s)", fd,
              sock_log_saddr(&saddr, ipstr, sizeof(ipstr)),
              params->source.pinet.ip);
        }
      else
        {
          ERR(ctx, "Failed to query %d bound address: %m", fd);
        }
      return true;
    }
  else
    {
      char ipstr[INET6_ADDRSTRLEN];

      ERR(ctx, "Failed to bind fd %d to source %s: %m",
          sock_log_saddr(&saddr, ipstr, sizeof(ipstr)));
    }
  return true;
}

static int socket_create_hinted(sukat_sock_t *ctx, struct addrinfo *p,
                                sukat_sock_endpoint_t *endpoint,
                                const struct sukat_sock_endpoint_params *params)
{
  int fd = socket(p->ai_family, p->ai_socktype |
                  SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      ERR(ctx, "Failed to create socket: %s", strerror(errno));
      return -1;
    }
  if (endpoint->is_server)
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
          int backlog = SOMAXCONN;

          if (params && params->listen)
            {
              backlog = params->listen;
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
      if (!params || !params->prebound ||
          prebind(ctx, fd, p->ai_family, params))
        {
          DBG_DEF(char ipstr[512]);

          if (connect(fd, p->ai_addr, p->ai_addrlen) != 0)
            {

              if (errno == EINPROGRESS)
                {
                  DBG(ctx, "Connect not completed with a single call");
                  endpoint->connect_in_progress = true;
                }
              else
                {
                  ERR(ctx, "Failed to connect to end-point: %s",
                      strerror(errno));
                  goto fail;
                }
            }
          else
            {
              // Don't conn_cb just yet.
            }
          DBG(ctx, "fd %d connection: %s", fd,
              fd_to_str(fd, ipstr, sizeof(ipstr)));
        }
      else
        {
          goto fail;
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
static int socket_create(sukat_sock_t *ctx,
                         struct sukat_sock_endpoint_params *params,
                         sukat_sock_endpoint_t *peer)
{
  int main_fd = -1;
  char socket_buf[128];
  union {
      struct sockaddr_un sun;
      struct sockaddr_tipc tipc;
      struct sockaddr_storage saddr;
  } socks;
  struct addrinfo hints = { }, *servinfo = NULL, *p;

  assert(peer != NULL && params != NULL);

  memset(&socks, 0, sizeof(socks));
  LOG(ctx, "%s: Creating",
      socket_log_params(params, socket_buf, sizeof(socket_buf)));
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
      if (!params->pinet.ip && !params->pinet.port)
        {
          p = &hints;
          hints.ai_family = hints.ai_addr->sa_family = AF_INET6;
          hints.ai_addrlen = sizeof(socks.saddr);
          hints.ai_socktype = SOCK_STREAM;
        }
      else
        {
          hints.ai_addr = NULL;
          hints.ai_flags = AI_PASSIVE;
          if (getaddrinfo(params->pinet.ip, params->pinet.port, &hints,
                          &servinfo) != 0)
            {
              ERR(ctx, "Failed to getaddrinfo for %s:%s", params->pinet.ip,
                  params->pinet.port);
              return -1;
            }
          p = servinfo;
        }
    }
  else
    {
      ERR(ctx, "domain %d socket not implemented", params->domain);
      return -1;
    }

  for (;p && main_fd == -1 ; p = p->ai_next)
    {
      main_fd = socket_create_hinted(ctx, p, peer, params);
      if (main_fd >= 0)
        {
          struct fd_info *info = &peer->info;

          info->slen = p->ai_addrlen;

          /* In the server case we might use port so add extra querying for
             these scenarios */
          if (params->server && is_inet(params->domain))
            {
              info->slen = sizeof(info->storage);
              if (getsockname(main_fd, &info->saddr, &info->slen) != 0)
                {
                  ERR(ctx, "Failed to query address server is bound to :%s",
                      strerror(errno));
                  close(main_fd);
                  continue;
                }
            }
          else
            {
              memcpy(&info->sin, p->ai_addr, p->ai_addrlen);
            }
          if (ctx)
            {
              ctx->n_connections++;
            }
          info->type= p->ai_socktype;

          LOG(ctx, "%s created", socket_log_fd_info(info, socket_buf,
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
                           sukat_sock_endpoint_t *endpoint, bool end)
{
  bool epollout_flag = endpoint->epollout;
  uint32_t events = EPOLLIN;

  if (!end)
    {
      events |= EPOLLOUT;
    }

  if (!(epollout_flag ^ end))
    {
      if (event_add_to_ctx(ctx, endpoint->info.fd, (void *)endpoint,
                           EPOLL_CTL_MOD, events) != true)
        {
          return false;
        }
      endpoint->epollout = (end) ? 0 : 1;
    }
  return true;
}

static void *get_caller_ctx(sukat_sock_t *ctx, sukat_sock_endpoint_t *endpoint)
{
  assert(ctx != NULL);
  if (endpoint && endpoint->endpoint_caller_ctx)
    {
      return endpoint->endpoint_caller_ctx;
    }
  return ctx->caller_ctx;
}

static void sock_destro_close(void *main_ctx, void *client_ctx)
{
  sukat_sock_t *ctx = (sukat_sock_t *)main_ctx;
  sukat_sock_endpoint_t *endpoint = (sukat_sock_endpoint_t *)client_ctx;

  if (endpoint)
    {
      uint32_t events = EPOLLIN;
      char dbg_buf[256];
      void *caller_ctx = get_caller_ctx(ctx, endpoint);

      if (endpoint->closed)
        {
          return;
        }
      LOG(ctx, "Removing endpoint %s",
          sukat_sock_endpoint_to_str(endpoint, dbg_buf, sizeof(dbg_buf)));
      if (endpoint->epollout)
        {
          events |= EPOLLOUT;
        }
      event_ctl(ctx->epoll_fd, endpoint->info.fd, NULL, EPOLL_CTL_DEL, events);
      free_cache(&endpoint->read_cache);
      free_cache(&endpoint->write_cache);
      close(endpoint->info.fd);
      if (!endpoint->destroyed)
        {
          USE_CB(ctx, conn_cb, caller_ctx, endpoint,
                 SUKAT_SOCK_CONN_EVENT_DISCONNECT);
        }
      if (endpoint->info.saddr.sa_family == AF_UNIX &&
          endpoint->info.sun.sun_path[0] != '\0')
        {
          if (unlink(endpoint->info.sun.sun_path))
            {
              ERR(ctx, "Failed to unlink sun socket %s",
                  endpoint->info.sun.sun_path);
            }
        }
      ctx->n_connections--;
    }
  else
    {
      LOG(ctx, "Removing main sock context");
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
    }
}

typedef enum event_handling_ret
{
  ERR_FATAL = -1,
  ERR_OK = 0,
  ERR_BREAK = 1,
} ret_t;

static bool ret_was_ok(sukat_sock_t *ctx, sukat_sock_endpoint_t *endpoint,
                       ssize_t ret)
{
  if (ret <= 0)
    {
      if (!(ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)))
        {
          void *caller_ctx = get_caller_ctx(ctx, endpoint);

          ERR(ctx, "Connection %s%s", (ret == 0) ? "closed" :
              "severed: ", (ret == -1) ? strerror(errno) : "");
          USE_CB(ctx, error_cb, caller_ctx, endpoint, errno);
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
static ret_t server_accept_cb(sukat_sock_t *ctx,
                              sukat_sock_endpoint_t *endpoint)
{
  struct sockaddr_storage saddr;
  socklen_t slen = sizeof(saddr);
  int fd = -1;

  assert(ctx != NULL && endpoint != NULL);

  while (destro_is_deleted(ctx->destro_ctx, NULL) != true &&
         (fd = accept(endpoint->info.fd, (struct sockaddr *)&saddr, &slen)) >= 0)
    {
      if (set_flags(ctx, fd) == true)
        {
          sukat_sock_endpoint_t *client =
            (sukat_sock_endpoint_t *)calloc(1, sizeof(*client));

          if (client)
            {
              client->info.fd = fd;
              client->info.type = endpoint->info.type;
              memcpy(&client->info.storage, &saddr, slen);

              if (event_add_to_ctx(ctx, fd, client, EPOLL_CTL_ADD,
                                   EPOLLIN) == true)
                {
                  LOG(ctx, "New client with fd %d", fd);
                  ctx->n_connections++;
                  USE_CB_WRET(ctx, client->endpoint_caller_ctx, conn_cb,
                              ctx->caller_ctx, client,
                              SUKAT_SOCK_CONN_EVENT_ACCEPTED);
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

static ret_t client_continue_connect(sukat_sock_t *ctx,
                                     sukat_sock_endpoint_t *endpoint)
{
  int opt;
  socklen_t len = sizeof(opt);
  void *caller_ctx = get_caller_ctx(ctx, endpoint);

  assert(ctx != NULL && endpoint != NULL);
  assert(!endpoint->is_server);

  if (getsockopt(endpoint->info.fd, SOL_SOCKET, SO_ERROR, &opt, &len) == 0)
    {
      if (!opt)
        {
          void *new_caller_ctx = NULL;
          char peer_data[128];

          LOG(ctx, "Connect completed to %s",
              socket_log_fd_info(&endpoint->info, peer_data,
                                 sizeof(peer_data)));
          endpoint->connect_in_progress = false;
          event_epollout(ctx, endpoint, true);
          USE_CB_WRET(ctx, new_caller_ctx, conn_cb, caller_ctx, endpoint,
                      SUKAT_SOCK_CONN_EVENT_CONNECT);
          if (new_caller_ctx)
            {
              endpoint->endpoint_caller_ctx = new_caller_ctx;
            }
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
      opt = errno;
    }
  USE_CB(ctx, error_cb, caller_ctx, endpoint, opt);
  return ERR_FATAL;
}

static bool keep_going(sukat_sock_t *ctx,
                       sukat_sock_endpoint_t *client)
{
  return !destro_is_deleted(ctx->destro_ctx,
                            (client) ? &client->destro_client_ctx : NULL);
}

/*!
 * Helper macro for determining if return value just implies blocking
 */
#define ITBLOCKS(_retval)                                                     \
  (_retval == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))

static ret_t read_stream(sukat_sock_t *ctx, sukat_sock_endpoint_t *endpoint)
{
  uint8_t buf[BUFSIZ];
  ssize_t read_now;
  bool blocked = false, disconnected = false;
  size_t n_read = 0;
  void *caller_ctx = get_caller_ctx(ctx, endpoint);

  assert(ctx != NULL && endpoint != NULL);
  DBG(ctx, "Reading stream fd %d", endpoint->info.fd);

  uncache(ctx, endpoint, buf, &n_read, false);

  while (blocked == false && disconnected == false)
    {
#define BUF_LEFT (sizeof(buf) - n_read)
      size_t processed;

      do
        {
          read_now = read(endpoint->info.fd, buf + n_read, BUF_LEFT);
        } while (read_now > 0 && (n_read += read_now) < sizeof(buf));
#undef BUF_LEFT
      if (ret_was_ok(ctx, endpoint, read_now) != true)
        {
          // If we have unprocessed stuff, read it before disconnecting.
          if (n_read)
            {
              disconnected = true;
            }
          else
            {
              return ERR_FATAL;
            }
        }
      else if (ITBLOCKS(read_now))
        {
          blocked = true;
        }

      DBG(ctx, "Read %zu bytes from %d", n_read, endpoint->info.fd);
#define UNPROCESSED (n_read - processed)

      processed = 0;
      while (UNPROCESSED && keep_going(ctx, endpoint))
        {
          size_t msg_len = 0;

          if (ctx->cbs.msg_len_cb)
            {
              int msg_len_query;

              USE_CB_WRET(ctx, msg_len_query, msg_len_cb, caller_ctx,
                          buf + processed, UNPROCESSED);
              if (!keep_going(ctx, endpoint))
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
                      if (cache(ctx, endpoint, buf + processed,
                                UNPROCESSED, false) != true)
                        {
                          USE_CB(ctx, error_cb, caller_ctx, endpoint, ENOMEM);
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
          USE_CB(ctx, msg_cb, caller_ctx, endpoint, buf + processed, msg_len);
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
#undef UNPROCESSED
    }

  return (disconnected == true) ? ERR_FATAL : ERR_OK;
}

static char *sock_hdr_or_peer_to_str(sukat_sock_endpoint_t *peer,
                                     struct msghdr *hdr,
                                     char *buf, size_t buf_len)
{
  if (hdr && hdr->msg_namelen)
    {
      return sock_log_saddr((struct sockaddr_storage *)&hdr->msg_name,
                            buf, buf_len);
    }
  else if (peer && peer->info.slen)
    {
      return sukat_sock_endpoint_to_str(peer, buf, buf_len);
    }
  snprintf(buf, buf_len, "unidentified");
  return buf;
}

static ret_t sock_dgram_loop(sukat_sock_t *ctx, int fd,
                             sukat_sock_endpoint_t *peer, struct msghdr *hdr,
                             void *caller_ctx)
{
  ssize_t ret = 0;
  size_t buffer_size = (ctx->max_packet_size) ? ctx->max_packet_size :
    BUFSIZ;
  uint8_t buf[buffer_size];
  char dbg_buf[256];
  struct iovec iov =
    {
      .iov_base = buf,
      .iov_len = buffer_size,
    };

  assert(ctx && peer && hdr);

  hdr->msg_iov = &iov;
  hdr->msg_iovlen = 1;
  do
    {
      hdr->msg_flags = 0;

      ret = recvmsg(fd, hdr, 0);
      if (ret > 0)
        {
          DBG(ctx, "Received %zu byte message from %s.", ret,
              sock_hdr_or_peer_to_str(peer, hdr, dbg_buf, sizeof(dbg_buf)));
          if (hdr->msg_name && hdr->msg_namelen)
            {
              peer->info.slen = hdr->msg_namelen;
            }
          if (hdr->msg_flags & MSG_TRUNC)
            {
              LOG(ctx, "%zd bytes of Truncated message received", ret);
            }
          if (ctx->cbs.msg_cb)
            {
              ctx->cbs.msg_cb(caller_ctx, peer, buf, ret);
            }
          else
            {
              ERR(ctx, "Message received, but no msg_cb given");
            }
        }
      else if (!(ITBLOCKS(ret)))
        {
          ERR(ctx, "%s while reading from %s socket%s%s",
              (ret == 0) ? "Disconnected" : "Error",
              sock_hdr_or_peer_to_str(peer, hdr, dbg_buf, sizeof(dbg_buf)),
              (ret == -1) ? ": " : "", (ret == -1) ? strerror(errno) : "");
          return ERR_FATAL;
        }
    } while (ret > 0);

  return ERR_OK;
}

static ret_t read_seqpacket(sukat_sock_t *ctx, sukat_sock_endpoint_t *client)
{
  struct msghdr hdr = { };

  assert(ctx && client);

  return sock_dgram_loop(ctx, client->info.fd, client, &hdr,
                         get_caller_ctx(ctx, client));
}

static ret_t read_connectionless(sukat_sock_t *ctx,
                                 sukat_sock_endpoint_t *endpoint)
{
  void *caller_ctx = get_caller_ctx(ctx, endpoint);
  // Make a temporary end-point for connectionless.
  sukat_sock_endpoint_t msg_from_endpoint = { };
  struct msghdr hdr = { };

  assert(ctx != NULL && endpoint != NULL && endpoint->info.fd >= 0);

  hdr.msg_name = &msg_from_endpoint.info.storage;
  hdr.msg_namelen = sizeof(msg_from_endpoint.info.storage);

  msg_from_endpoint.info.type = endpoint->info.type;
  msg_from_endpoint.info.fd = -1;
  msg_from_endpoint.stack_dummy = true;

  return sock_dgram_loop(ctx, endpoint->info.fd, &msg_from_endpoint, &hdr,
                         caller_ctx);
}

/*!
 * Send any cached data. Should only happen on connection oriented sockets
 *
 * @param ctx Main context.
 * @param client If non-null, client context. If NULL we're using socket in
 *        main.
 */
static enum sukat_sock_send_return
send_cached(sukat_sock_t *ctx, sukat_sock_endpoint_t *endpoint)
{
  struct rw_cache *cache = &endpoint->write_cache;

  if (cache->data && cache->len)
    {
      size_t sent = 0;
      ssize_t ret;

      DBG(ctx, "Finishing send of %zu bytes to fd %d",
          cache->len, endpoint->info.fd);

      do
        {
          ret = write(endpoint->info.fd, cache->data + sent, cache->len - sent);
        } while (ret > 0 && (sent  += ret) < cache->len);
      if (ret_was_ok(ctx, endpoint, ret) != true)
        {
          return SUKAT_SEND_ERROR;
        }
      if (sent == cache->len)
        {
          free_cache(cache);
          if (event_epollout(ctx, endpoint, true) != true)
            {
              return SUKAT_SEND_ERROR;
            }
          /* Stop waiting for EPOLLOUT */
        }
      else
        {
          /* If we sent 0, we don't need to do anything, just try again. */
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

static ssize_t sock_splice_intermediary(sukat_sock_t *ctx, int fd_in,
                                        int fd_out, int *inter_pipes)
{
  ssize_t ret;
  ssize_t total_spliced = 0;
#define SPLICE_FLAGS (SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK)

  do
    {
      ret = splice(fd_in, NULL, inter_pipes[1], NULL, PIPE_BUF, SPLICE_FLAGS);
      DBG(ctx, "Splice returned %zd from fd %d", ret, fd_in);
      if (ret > 0 || ITBLOCKS(ret))
        {
          ret =
            splice(inter_pipes[0], NULL, fd_out, NULL, PIPE_BUF, SPLICE_FLAGS);
          DBG(ctx, "Splice other side returned %zd to fd %d", ret, fd_out);
          if (ret > 0)
            {
              total_spliced += ret;
            }
        }
    } while (ret > 0);
  if (!ITBLOCKS(ret))
    {
      ERR(ctx, "Failed to splice data: %s",
          (ret == 0) ? "Disconnected" : strerror(errno));
      return -1;
    }
  return total_spliced;
}

static ssize_t sock_splice(sukat_sock_t *ctx, int fd_in, int fd_out,
                           int *inter_pipes)
{
  ssize_t total_spliced = 0;

  if (inter_pipes)
    {
      total_spliced = sock_splice_intermediary(ctx, fd_in, fd_out, inter_pipes);
    }
  else
    {
      ssize_t ret;

      do
        {
          ret = splice(fd_in, NULL, fd_out, NULL, PIPE_BUF, SPLICE_FLAGS);
          if (ret > 0)
            {
              total_spliced += ret;
            }
        }
      while (ret > 0);
      if (!ITBLOCKS(ret))
        {
          ERR(ctx, "Failed to splice data: %s",
              (ret == 0) ? "Disconnected" : strerror(errno));
          return -1;
        }
    }

  return total_spliced;
}

#undef SPLICE_FLAGS

static ret_t sock_splice_event(sukat_sock_t *ctx,
                               sukat_sock_endpoint_t *endpoint)
{
  void *caller_ctx = get_caller_ctx(ctx, endpoint);
  int target_fd = -1, *intermediary_fds = NULL;

  assert(ctx != NULL && endpoint != NULL && ctx->cbs.splice_cb != NULL);
  ctx->cbs.splice_cb(caller_ctx, endpoint, &target_fd, &intermediary_fds);
  if (target_fd >= 0)
    {
      ssize_t ret =
        sock_splice(ctx, endpoint->info.fd, target_fd,intermediary_fds);

      return (ret >= 0) ? ERR_OK : ERR_FATAL;
    }
  else
    {
      ERR(ctx, "Invalid fd %d given for splicing", target_fd);
    }

  return ERR_FATAL;
}

static ret_t event_read(sukat_sock_t *ctx,
                        sukat_sock_endpoint_t *endpoint)
{
  if (ctx->cbs.splice_cb)
    {
      return sock_splice_event(ctx, endpoint);
    }
  if (socket_connection_oriented(endpoint->info.type))
    {
      if (endpoint->info.type == SOCK_SEQPACKET)
        {
          return read_seqpacket(ctx, endpoint);
        }
      else
        {
          return read_stream(ctx, endpoint);
        }
    }
  return read_connectionless(ctx, endpoint);
}

static void event_non_epollin(sukat_sock_t *ctx,
                              sukat_sock_endpoint_t *peer, uint32_t events)
{
  void *caller_ctx = get_caller_ctx(ctx, peer);
  int errval = (events & EPOLLHUP) ? ECONNABORTED :
    ECONNRESET;

  ERR(ctx, "%s event received from %s connection",
      (events == EPOLLERR) ? "Error" : "Disconnect",
      (peer) ? "peer" : "main");
  USE_CB(ctx, error_cb, caller_ctx, peer, errval);
}

static void event_handle(sukat_sock_t *ctx, struct epoll_event *event)
{
  sukat_sock_endpoint_t *endpoint = (sukat_sock_endpoint_t *)(event->data.ptr);
  if (endpoint->closed)
    {
      return;
    }
  if (event->events & !(EPOLLIN | EPOLLOUT))
    {
      event_non_epollin(ctx, NULL, event->events);
      return;
    }
  if (endpoint->is_server)
    {
      if (socket_connection_oriented(endpoint->info.type))
        {
          server_accept_cb(ctx, endpoint);
        }
      else
        {
          event_read(ctx, endpoint);
        }
    }
  else
    {
      ret_t ret = ERR_OK;

      if (endpoint->connect_in_progress)
        {
          ret = client_continue_connect(ctx, endpoint);
        }
      else if (event->events & EPOLLOUT)
        {
          assert(endpoint->write_cache.len > 0);
          if (send_cached(ctx, endpoint) == SUKAT_SEND_ERROR)
            {
              ret = ERR_FATAL;
            }
        }
      else
        {
          ret = event_read(ctx, endpoint);
        }
      if (ret != ERR_OK)
        {
          destro_delete(ctx->destro_ctx, &endpoint->destro_client_ctx);
        }
    }
}

int sukat_sock_read(sukat_sock_t *ctx, int timeout)
{
  int nfds;
  ret_t ret = ERR_OK;

  if (!ctx)
    {
      errno = EINVAL;
      return -1;
    }
  destro_cb_enter(ctx->destro_ctx);
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
          if (errno == EINTR)
            {
              goto out;
            }
          ret = ERR_FATAL;
          goto out;
        }
      for (i = 0; i < (size_t)nfds && ret == ERR_OK ; i++)
        {
          event_handle(ctx, &new_events[i]);
        }
      if (timeout > 0)
        {
          timeout = 0;
        }
    } while (nfds > 0 && destro_is_deleted(ctx->destro_ctx, NULL) != true
             && ctx->n_connections > 0 && ret != ERR_FATAL);

out:
  if (ret == ERR_BREAK)
    {
      ret = ERR_OK;
    }
  destro_cb_exit(ctx->destro_ctx);
  return (int)ret;
}

sukat_sock_t *sukat_sock_create(struct sukat_sock_params *params,
                                struct sukat_sock_cbs *cbs)
{
  sukat_sock_t *ctx;
  struct destro_params dparams = { };
  struct destro_cbs dcbs = { };

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
  if (cbs)
    {
      memcpy(&ctx->cbs, cbs, sizeof(*cbs));
    }
  ctx->epoll_fd = ctx->master_epoll_fd = -1;
  ctx->caller_ctx = params->caller_ctx;
  ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  ctx->max_packet_size = params->max_packet_size;
  if (ctx->epoll_fd < 0) {
      ERR(ctx, "Failed to create epoll fd: %s", strerror(errno));
      goto fail;
  }
  if (params->master_epoll_fd_set)
    {
      struct epoll_event event =
        {
          .events = EPOLLIN,
          .data =
            {
              .ptr = ctx
            }
        };

      if (epoll_ctl(params->master_epoll_fd, EPOLL_CTL_ADD,
                    ctx->epoll_fd, &event))
        {
          ERR(ctx, "Failed to add epoll fd %d to master epoll fd %d: %s",
              ctx->epoll_fd, params->master_epoll_fd, strerror(errno));
          goto fail;
        }
      ctx->master_epoll_fd = params->master_epoll_fd;
    }
  dcbs.close = sock_destro_close;
  if (cbs)
    {
      dcbs.log_cb = cbs->log_cb;
    }
  dparams.main_ctx = ctx;
  ctx->destro_ctx = destro_create(&dparams, &dcbs);
  if (!ctx->destro_ctx)
    {
      ERR(ctx, "Failed to create delayed destruction context");
      goto fail;
    }

  return ctx;

fail:
  sukat_sock_destroy(ctx);
  return NULL;
}

sukat_sock_endpoint_t
*sukat_sock_endpoint_add(sukat_sock_t *ctx,
                         struct sukat_sock_endpoint_params *params)
{
  if (!params)
    {
      ERR(ctx, "No parameters for end-point");
      return NULL;
    }
  if (ctx)
    {
      sukat_sock_endpoint_t *endpoint =
        (sukat_sock_endpoint_t *)calloc(1, sizeof(*endpoint));

        {
          char parambuf[128];

          LOG(ctx, "%s endpoint %s",
              (params->server) ? "Hosting" : "Connecting to",
              socket_log_params(params, parambuf, sizeof(parambuf)));
          }

      if (endpoint)
        {
          endpoint->info.fd = -1;
          endpoint->is_server = params->server;
          endpoint->endpoint_caller_ctx = params->caller_ctx;
          endpoint->info.type = params->type;
          endpoint->info.fd = socket_create(ctx, params, endpoint);
          if (endpoint->info.fd >= 0)
            {
              if (event_add_to_ctx(ctx, endpoint->info.fd, (void *)endpoint,
                                   EPOLL_CTL_ADD, EPOLLIN) == true)
                {
                  if (endpoint->connect_in_progress)
                    {
                      event_epollout(ctx, endpoint, false);
                    }
                  else if (!endpoint->is_server
                           && socket_connection_oriented(params->type))
                    {
                      bool destroyed_in_between;
                      void *new_caller_ctx = NULL;

                      destro_cb_enter(ctx->destro_ctx);
                      USE_CB_WRET(ctx, new_caller_ctx, conn_cb,
                                  ctx->caller_ctx, endpoint,
                                  SUKAT_SOCK_CONN_EVENT_CONNECT);
                      destroyed_in_between =
                        destro_is_deleted(ctx->destro_ctx, NULL);
                      destro_cb_exit(ctx->destro_ctx);

                      if (destroyed_in_between)
                        {
                          // Resources freed already
                          return NULL;
                        }
                      else if (new_caller_ctx)
                        {
                          endpoint->endpoint_caller_ctx = new_caller_ctx;
                        }
                    }
                  return endpoint;

                }
              close(endpoint->info.fd);
            }
          free(endpoint);
        }
      else
        {
          ERR(ctx, "Failed to allocate memory for endpoint: %s",
              strerror(errno));
        }
    }
  return NULL;
}

void sukat_sock_destroy(sukat_sock_t *ctx)
{
  if (ctx)
    {
      if (ctx->destro_ctx)
        {
          destro_delete(ctx->destro_ctx, NULL);
        }
      else
        {
          sock_destro_close(ctx, NULL);
          free(ctx);
        }
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
                                                   sukat_sock_endpoint_t *peer,
                                                   uint8_t *msg, size_t msg_len)
{
  ssize_t ret;
  size_t sent = 0;
  int fd;

  assert(ctx != NULL && peer != NULL);
  DBG(ctx, "Sending %zu bytes of stream to %d", msg_len, peer->info.fd);
  fd = peer->info.fd;

  do
    {
      ret = write(fd, msg + sent, msg_len - sent);
    }
  while (ret > 0 && (sent += ret) < msg_len);
  if (ret_was_ok(ctx, peer, ret) == true)
    {
      /* If we cant send a single byte, just return EAGAIN */
      if (sent == 0)
        {
          return SUKAT_SEND_EAGAIN;
        }
      if (cache(ctx, peer, msg + sent, msg_len - sent, true) == true)
        {
          if ((msg_len == sent) || event_epollout(ctx, peer, false) == true)
            {
              return SUKAT_SEND_OK;
            }
        }
    }
  return SUKAT_SEND_ERROR;
}

static bool sock_endpoint_to_client(sukat_sock_t *ctx,
                                    sukat_sock_endpoint_t *client,
                                    sukat_sock_endpoint_t *to_fill)
{
  struct addrinfo info = { };

  assert(client && to_fill);
  info.ai_family = client->info.storage.ss_family;
  info.ai_socktype = client->info.type ;
  info.ai_addrlen = client->info.slen;
  info.ai_addr = &client->info.saddr;
  to_fill->info.slen = client->info.slen;
  to_fill->info.type = client->info.type;
  memcpy(&to_fill->info.storage, &client->info.storage,
         client->info.slen);
  to_fill->info.fd = socket_create_hinted(ctx, &info, to_fill, NULL);
  if (to_fill->info.fd < 0)
    {
      char endpoint_str[256];

      ERR(ctx, "Failed to create socket to %s",
          sukat_sock_endpoint_to_str(client, endpoint_str,
                                     sizeof(endpoint_str)));
      return false;
    }
  return true;
}

static enum sukat_sock_send_return
  sock_send_dgram(sukat_sock_t *ctx, int fd, uint8_t *msg, size_t msg_len,
                  struct msghdr *hdr)
{
  ssize_t ret;
  struct iovec iov =
    {
      .iov_base = msg,
      .iov_len = msg_len
    };

  hdr->msg_iov = &iov;
  hdr->msg_iovlen = 1;

  ret = sendmsg(fd, hdr, 0);
  if (ret <= 0)
    {
      if (!ITBLOCKS(ret))
        {
          ERR(ctx, "Failed to send %u byte message: %s", msg_len,
              (ret == 0) ? "Disconnected" : strerror(errno));
          return SUKAT_SEND_ERROR;
        }
      return SUKAT_SEND_EAGAIN;
    }
  else if ((size_t)ret != msg_len)
    {
      ERR(ctx, "Sent only %zu bytes of full %u byte message", ret, msg_len);
    }

  return SUKAT_SEND_OK;
}

static enum sukat_sock_send_return send_dgram_msg(sukat_sock_t *ctx,
                                                  sukat_sock_endpoint_t *client,
                                                  uint8_t *msg, size_t msg_len,
                                                  sukat_sock_endpoint_t *source)
{
  enum sukat_sock_send_return retval;
  sukat_sock_endpoint_t on_the_fly = { };
  struct msghdr hdr = { };
  DBG_DEF(char endpoint_str[256]);

  on_the_fly.info.fd = -1;

  assert(client && msg && msg_len);
  if (!source)
    {
      if (!sock_endpoint_to_client(ctx, client, &on_the_fly))
        {
          return SUKAT_SEND_ERROR;
        }
      source = &on_the_fly;
    }
  hdr.msg_namelen = client->info.slen;
  hdr.msg_name = &client->info.storage;

  DBG(ctx, "Sending %u byte to %s", msg_len,
      sukat_sock_endpoint_to_str(client, endpoint_str, sizeof(endpoint_str)));

  retval = sock_send_dgram(ctx, source->info.fd, msg, msg_len, &hdr);
  if (on_the_fly.info.fd != -1)
    {
      close(on_the_fly.info.fd);
    }
  return retval;
}

static enum sukat_sock_send_return send_seqm_msg(sukat_sock_t *ctx,
                                                 sukat_sock_endpoint_t *client,
                                                 uint8_t *msg, size_t msg_len)
{
  struct msghdr hdr = { };
  DBG_DEF(char endpoint_str[256]);

  assert(ctx && client && msg && msg_len);

  DBG(ctx, "Sending %u byte to %s", msg_len,
      sukat_sock_endpoint_to_str(client, endpoint_str, sizeof(endpoint_str)));

  return sock_send_dgram(ctx, client->info.fd, msg, msg_len, &hdr);
}

#undef ITBLOCKS

enum sukat_sock_send_return sukat_send_msg(sukat_sock_t *ctx,
                                           sukat_sock_endpoint_t *peer,
                                           uint8_t *msg, size_t msg_len,
                                           sukat_sock_endpoint_t *source)
{
  enum sukat_sock_send_return ret = SUKAT_SEND_OK;

  if (!ctx || !peer || !msg || !msg_len)
    {
      ERR(ctx, "Invalid parameters to send: ctx: %p peer: %p msg: %p "
          "msg_len: %u", ctx, peer, msg, msg_len);
      return SUKAT_SEND_ERROR;
    }
  if (peer->connect_in_progress)
    {
      ERR(ctx, "Cannot send message, since connect still in progress");
      errno = EINPROGRESS;
      return SUKAT_SEND_ERROR;
    }

  ret = send_cached(ctx, peer);
  if (ret != SUKAT_SEND_OK)
    {
      return ret;
    }
  if (socket_connection_oriented(peer->info.type))
    {
      if (source)
        {
          ERR(ctx, "Source given for connection oriented send");
          // I guess its okay to send anyway.
        }
      if (peer->info.type == SOCK_STREAM)
        {
          return send_stream_msg(ctx, peer, msg, msg_len);
        }
      return send_seqm_msg(ctx, peer, msg, msg_len);
    }
  return send_dgram_msg(ctx, peer, msg, msg_len, source);
}

void sukat_sock_disconnect(sukat_sock_t *ctx, sukat_sock_endpoint_t *peer)
{
  if (ctx != NULL && peer != NULL)
    {
      peer->destroyed = true;
      destro_delete(ctx->destro_ctx, &peer->destro_client_ctx);
    }
}

int get_domain(sukat_sock_endpoint_t *endpoint)
{
  return endpoint->info.storage.ss_family;
}

ssize_t sukat_sock_splice_to(sukat_sock_t *ctx, sukat_sock_endpoint_t *endpoint,
                             int fd_in, int *inter_pipes)
{
  if (!ctx || !endpoint || fd_in < 0)
    {
      ERR(ctx, "Invalid argument to splicing: ctx: %p endpoint %p fd %d",
          ctx, endpoint, fd_in);
      return -1;
    }
  return sock_splice(ctx, fd_in, endpoint->info.fd, inter_pipes);
}

uint16_t sukat_sock_get_port(sukat_sock_endpoint_t *endpoint)
{
  if (endpoint)
    {
      int domain = get_domain(endpoint);

      if (domain == AF_INET || domain == AF_INET6)
        {
          return ntohs(endpoint->info.sin.sin_port);
        }
    }
  return 0;
}

/*! }@ */
