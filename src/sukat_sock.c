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

struct client_ctx
{
  int fd; //!< Accepted fd.
  void *client_caller_ctx; //!< Specific context if set. Otherwise NULL.
  sukat_sock_ctx_t *main_ctx; //!< Backwards pointer to sukat_sock_ctx_t.
};

struct sukat_sock_ctx
{
  /*TODO: Somehow refactor params out and replace with combination of params
   * flags and saddr */
  struct sukat_sock_params params;
  union
    {
      struct sockaddr_un un;
      struct sockaddr_tipc tipc;
    } saddr;
  struct sukat_sock_cbs cbs;
  int fd; //!< Main fd for accept to server or connected fd for client.
  bool external_event_ctx;
  sukat_tree_ctx_t *client_tree;
  bool connect_in_progress;
};

static bool socket_connection_oriented(struct sukat_sock_params *params)
{
  assert(params);

  if (params->type == SOCK_DGRAM || params->type == SOCK_RDM)
    {
      return false;
    }
  return true;
}

static char *socket_log(sukat_sock_ctx_t *ctx, char *buf, size_t buf_len)
{
  size_t n_used = 0;

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

  SAFEPUT((ctx->params.server) ? "Server ": "Client ");
  switch (ctx->params.domain)
    {
    case AF_UNIX:
      SAFEPUT("UNIX %s%s", (ctx->params.specific.abstract) ? "abstract " : "",
              ctx->params.id.name);
      break;
    case AF_TIPC:
      SAFEPUT("TIPC type %d service %d", ctx->params.id.port_type,
              ctx->params.specific.port_instance);
      break;
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      SAFEPUT("INET %s:%s", (ctx->params.id.ip) ? ctx->params.id.ip : "any",
              ctx->params.specific.port);
      break;
    default:
      SAFEPUT("Unknown %d", ctx->params.domain);
      break;
    }

  return buf;
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

static int socket_create(sukat_sock_ctx_t *ctx)
{
  int fd = -1;
  union {
      struct sockaddr_tipc tipc;
      struct sockaddr_un un;
  } sockaddr;
  size_t addrlen = 0;
  char socket_buf[128];
  int proto = 0;

  memset(&sockaddr, 0, sizeof(sockaddr));
  if (ctx->params.domain != AF_TIPC)
    {
      proto = SOCK_NONBLOCK | SOCK_CLOEXEC;
    }
  LOG(ctx, "%s: Creating", socket_log(ctx, socket_buf, sizeof(socket_buf)));
  fd = socket(ctx->params.domain, ctx->params.type, proto);
  if (ctx->params.domain == AF_TIPC)
    {
      if (set_flags(ctx, fd) != true)
        {
          goto fail;
        }
    }
  if (fd <= 0)
    {
      ERR(ctx, "Failed to create socket: %s", strerror(errno));
      goto fail;
    }
  if (ctx->params.domain == AF_UNIX)
    {
      size_t n_used = 0;
      if (ctx->params.id.name == NULL)
        {
          ERR(ctx, "No name given for AF_UNIX socket");
          goto fail;
        }
      sockaddr.un.sun_family = AF_UNIX;
      if (ctx->params.specific.abstract)
        {
          *sockaddr.un.sun_path = '\0';
        }
      snprintf(sockaddr.un.sun_path + n_used, sizeof(sockaddr.un.sun_path) -
               n_used - 1, "%s", ctx->params.id.name);
      addrlen = sizeof(sockaddr.un);
    }
  else if (ctx->params.domain == AF_TIPC)
    {
      sockaddr.tipc.family = AF_TIPC;
      //TODO: Add these things as parameter.
      if (ctx->params.server)
        {
          sockaddr.tipc.addrtype = TIPC_ADDR_NAMESEQ;
          sockaddr.tipc.addr.nameseq.lower = ctx->params.specific.port_instance;
          sockaddr.tipc.addr.nameseq.upper = ctx->params.specific.port_instance;
          sockaddr.tipc.scope = TIPC_ZONE_SCOPE;
          sockaddr.tipc.addr.nameseq.type = ctx->params.id.port_type;
        }
      else
        {
          sockaddr.tipc.addrtype = TIPC_ADDR_NAME;
          sockaddr.tipc.addr.name.name.instance =
            ctx->params.specific.port_instance;
          sockaddr.tipc.addr.name.domain = 0;
          sockaddr.tipc.addr.name.name.type = ctx->params.id.port_type;
        }
      addrlen = sizeof(sockaddr.tipc);
    }
  else
    {
      ERR(ctx, "Not implemented");
      goto fail;
    }
  if (ctx->params.server)
    {
      if (bind(fd, (struct sockaddr *)&sockaddr, addrlen) != 0)
        {
          ERR(ctx, "Failed to bind to socket: %s", strerror(errno));
          goto fail;
        }
      if (socket_connection_oriented(&ctx->params))
        {
          if (ctx->params.listen == 0)
            {
              ctx->params.listen = 16;
            }
          if (listen(fd, ctx->params.listen) != 0)
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
  memcpy(&ctx->saddr, &sockaddr, sizeof(sockaddr));

  LOG(ctx, "%s created", socket_log(ctx, socket_buf, sizeof(socket_buf)));

  /* Remove any dangling char-pointers */
  memset(&ctx->params.id, 0, sizeof(ctx->params.id));
  memset(&ctx->params.specific, 0, sizeof(ctx->params.specific));

  //TODO save some sockaddr_storage for debugging as union of parameters.*/

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

void server_accept_cb(void *sock_ctx, int fd, uint32_t events)
{
  sukat_sock_ctx_t *ctx = (sukat_sock_ctx_t *)sock_ctx;
  struct sockaddr_storage saddr;
  socklen_t slen = sizeof(saddr);
  struct client_ctx *client;
  int client_fd;

  if (events != EPOLLIN)
    {
      ERR(ctx, "Received event %x", events);
      return;
    }

  client_fd = accept(fd, (struct sockaddr *)&saddr, &slen);
  if (client_fd < 0)
    {
      ERR(ctx, "Failed to accept: %s", strerror(errno));
      return;
    }
  LOG(ctx, "New client with fd %d", client_fd);
  client = (struct client_ctx *)calloc(1, sizeof(*client));
  if (!client)
    {
      ERR(ctx, "No memory to accept new clients: %s", strerror(errno));
      close(fd);
      return;
    }
  client->fd = fd;
  client->main_ctx = ctx;

  if (sukat_event_add(ctx->params.event_ctx, client, client_fd, read_client_cb,
                      EPOLLIN) != true)
    {
      close(fd);
      free(client);
      return;
    }
  if (ctx->cbs.conn_cb)
    {
       client->client_caller_ctx =
         ctx->cbs.conn_cb(ctx->params.caller_ctx, fd, &saddr, slen, false);
    }
}

void client_continue_connect(void *sock_ctx, int fd, uint32_t events)
{
  sukat_sock_ctx_t *ctx = (sukat_sock_ctx_t *)sock_ctx;
  socklen_t slen;

  if (events != EPOLLIN)
    {
      ERR(ctx, "During connect, client received event %u", events);
      return;
    }
  if (ctx->params.domain == AF_TIPC)
    {
      slen = sizeof(ctx->saddr.tipc);
    }
  else if (ctx->params.domain == AF_UNIX)
    {
      slen = sizeof(ctx->saddr.un);
    }
  else
    {
      ERR(ctx, "Not implemented");
      return;
    }
  if (connect(fd, (struct sockaddr *)&ctx->saddr.tipc, slen) != 0)
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
    }
  else
    {
      //TODO Make cleaner.
      LOG(ctx, "Connected!");
    }
}

sukat_sock_ctx_t *sukat_sock_create(struct sukat_sock_params *params,
                                    struct sukat_sock_cbs *cbs)
{
  sukat_sock_ctx_t *ctx;

  ctx = (sukat_sock_ctx_t *)calloc(1, sizeof(*ctx));
  if (!ctx)
    {
      return NULL;
    }
  ctx->fd = -1;
  if (params)
    {
      memcpy(&ctx->params, params, sizeof(*params));
    }
  if (cbs)
    {
      memcpy(&ctx->cbs, cbs, sizeof(*cbs));
    }
  ctx->fd = socket_create(ctx);
  if (ctx->fd < 0)
    {
      goto fail;
    }
  if (!ctx->params.event_ctx)
    {
      struct sukat_event_cbs event_cbs =
        {
          .log_cb = (cbs) ? cbs->log_cb : NULL
        };

      ctx->params.event_ctx = sukat_event_create(NULL, &event_cbs);
      if (!ctx->params.event_ctx)
        {
          ERR(ctx, "Failed to create event context");
          goto fail;
        }
    }
  else
    {
      ctx->external_event_ctx = true;
    }
  if (ctx->params.server)
    {
      if (socket_connection_oriented(&ctx->params)) {
          if (sukat_event_add(ctx->params.event_ctx, ctx, ctx->fd,
                              server_accept_cb, EPOLLIN) != true)
            {
              goto fail;
            }
      }
      else
        {
          //TODO
        }
    }
  else
    {
      if (ctx->connect_in_progress)
        {
          if (sukat_event_add(ctx->params.event_ctx, ctx, ctx->fd,
                              client_continue_connect, EPOLLIN) != true)
            {
              goto fail;
            }
        }
      else
        {
          //TODO
        }
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
      if (ctx->fd >= 0)
        {
          close(ctx->fd);
        }
      if (ctx->params.event_ctx && !ctx->external_event_ctx)
        {
          sukat_event_destroy(ctx->params.event_ctx);
        }
      if (ctx->client_tree)
        {
          sukat_tree_destroy(ctx->client_tree);
          // TODO: destroy stuff in da tree.
        }
      free(ctx);
    }
}

/*! }@ */
