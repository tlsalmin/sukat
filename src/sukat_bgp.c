/*!
 * @file sukat_bgp.h
 * @brief BGP library implementation.
 *
 * @addtogroup sukat_bgp
 * @{
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include "sukat_bgp.h"
#include "sukat_log_internal.h"
#include "sukat_sock.h"
#include "delayed_destruction.h"

#define BGP_VERSION 4

#define LOG_W_PEER(_ctx, _peer, _lvl, _fmt, ...)                              \
  do                                                                          \
    {                                                                         \
      char peerbuf[64];                                                       \
                                                                              \
      snprintf(peerbuf, sizeof(peerbuf), "peer AS: %hu BGP_ID: %u",           \
               _peer->id.as_num, _peer->id.bgp_id);                           \
      _lvl(_ctx, "%s: " _fmt, peerbuf, ##__VA_ARGS__);                        \
    }                                                                         \
  while (0)

#define DBG_PEER(_ctx, _peer, _fmt, ...)                                      \
  LOG_W_PEER(_ctx, _peer, DBG, _fmt,## __VA_ARGS__)

#define LOG_PEER(_ctx, _peer, _fmt, ...)                                      \
  LOG_W_PEER(_ctx, _peer, LOG, _fmt,## __VA_ARGS__)

#define ERR_PEER(_ctx, _peer, _fmt, ...)                                      \
  LOG_W_PEER(_ctx, _peer, ERR, _fmt,## __VA_ARGS__)

struct sukat_bgp_ctx_t
{
  struct sukat_bgp_cbs cbs;
  sukat_sock_t *sock_ctx;
  void *caller_ctx;
  struct {
      uint8_t unused:8;
  } flags;
  destro_t *destro_ctx;
  uint16_t hold_time;
  sukat_sock_endpoint_t *endpoint;
  bgp_id_t id;
};

struct sukat_bgp_peer_ctx
{
  destro_client_t destro_client_ctx;
  sukat_sock_endpoint_t *sock_peer;
  struct {
      uint8_t opened:1; //!< True if we have received a BGP_MSG_OPEN.
      uint8_t destroyed:1; //!< Explicitly destroyed by library user.
      uint8_t accepted_from_server_socket:1;
      uint8_t open_confirmed:1; //!< Open confirmed by KEEPALIVE
      uint8_t unused:4;
  } flags;
  bgp_id_t id;
  sukat_bgp_t *main_ctx;
  void *caller_ctx;
};

enum bgp_msg_type
{
  BGP_MSG_OPEN = 1,
  BGP_MSG_UPDATE,
  BGP_MSG_NOTIFICATION,
  BGP_MSG_KEEPALIVE
};

const char *bgp_msg_type_strs[] =
{
  "OPEN",
  "UPDATE",
  "NOTIFICATION",
  "KEEPALIVE",
  "UNKNOWN"
};

static const char *msg_type_to_str(enum bgp_msg_type type)
{
  if (type >= BGP_MSG_OPEN && type <= BGP_MSG_KEEPALIVE)
    {
      return bgp_msg_type_strs[type - 1];
    }
  return bgp_msg_type_strs[4];
}

#pragma pack(1)
/* See https://www.ietf.org/rfc/rfc4271.txt */
struct bgp_hdr
{
  uint8_t marker[16];
  uint16_t length;
  uint8_t type;
};

struct bgp_withdrawn_route
{
  uint8_t length;
  uint8_t prefix[];
};

struct bgp_open
{
  uint8_t version;
  uint16_t as_num;
  uint16_t hold_time;
  uint32_t bgp_id;
  uint8_t opt_param_len;
  uint8_t opt_param[];
};

struct bgp_notification
{
  uint8_t error;
  uint8_t error_subcode;
  uint8_t data[];
};

struct bgp_msg
{
  struct bgp_hdr hdr;
  union
    {
      struct bgp_open open;
      struct bgp_notification notification;
    } msg;
};
#pragma pack()

static int bgp_msg_len_cb(void *ctx, uint8_t *buf, size_t buf_len)
{
  sukat_bgp_t *bgp_ctx = (sukat_bgp_t *)ctx;
  struct bgp_msg *msg = (struct bgp_msg *)buf;

  if (buf_len < sizeof(msg->hdr))
    {
      return 0;
    }
  (void)bgp_ctx;
  return ntohs(msg->hdr.length);
}

static bool msg_is_sane(sukat_bgp_t *bgp_ctx, uint8_t *buf, size_t buf_len)
{
  struct bgp_msg *msg = (struct bgp_msg *)buf;
  uint16_t exam16;

  if (buf_len >= sizeof(msg->hdr))
    {
      size_t msg_len = ntohs(msg->hdr.length);

      if (msg_len == buf_len)
        {
          // RFC 4271 mandates these values.
          if (msg_len >= 19 && msg_len <= 4096)
            {
              switch (msg->hdr.type)
                {
                case BGP_MSG_OPEN:
                  exam16 = sizeof(msg->hdr) + sizeof(msg->msg.open) +
                    msg->msg.open.opt_param_len;
                  if (msg_len == exam16)
                    {
                      exam16 = ntohs(msg->msg.open.hold_time);
                      if (exam16 == 0 || exam16 >= 3)
                        {
                          return true;
                        }
                      ERR(bgp_ctx, "Invalid hold time %u", exam16);
                    }
                  else
                    {
                      ERR(bgp_ctx, "Message length %u doesn't match calculated "
                          "length %u", msg_len, exam16);
                    }
                  break;
                case BGP_MSG_KEEPALIVE:
                  if (buf_len == 19)
                    {
                      return true;
                    }
                  ERR(bgp_ctx, "Invalid keepalive length %hu", msg_len);
                case BGP_MSG_NOTIFICATION:
                  if (msg_len >=
                      sizeof(msg->hdr) + sizeof(msg->msg.notification))
                    {
                      return true;
                    }
                  else
                    {
                      ERR(bgp_ctx, "Too short (%hu) message for notification",
                          msg_len);
                    }
                  break;
                default:
                  ERR(bgp_ctx, "Unknown message type %u", msg->hdr.type);
                  break;
                }
            }
          else
            {
              ERR(bgp_ctx, "Invalid message length %u", msg_len);
            }
        }
    }
  else
    {
      ERR(bgp_ctx, "Message length %u not long enough for header", buf_len);
    }
  return false;
}

static void msg_header_fill(struct bgp_msg *msg, enum bgp_msg_type type,
                            size_t len)
{
  msg->hdr.length = htons(len);
  msg->hdr.type = type;
  memset(msg->hdr.marker, 1, sizeof(msg->hdr.marker));
}

static enum sukat_sock_send_return msg_send_keepalive(sukat_bgp_t *bgp_ctx,
                                                      sukat_bgp_peer_t *peer)
{
  struct bgp_msg msg = { };
  size_t msg_len = sizeof(msg.hdr);

  assert(bgp_ctx != NULL && peer != NULL);
  msg_header_fill(&msg, BGP_MSG_KEEPALIVE, msg_len);
  DBG_PEER(bgp_ctx, peer, "Sending KEEPALIVE");

  return sukat_send_msg(bgp_ctx->sock_ctx, peer->sock_peer, (uint8_t *)&msg,
                        msg_len);
}

static void bgp_msg_cb(void *ctx,
                       __attribute__((unused)) sukat_sock_endpoint_t *client,
                       uint8_t *buf, size_t buf_len)
{
  struct bgp_msg *msg = (struct bgp_msg *)buf;
  sukat_bgp_peer_t *bgp_peer = (sukat_bgp_peer_t *)ctx;
  sukat_bgp_t *bgp_ctx;
  size_t msg_len;
  void *caller_ctx;

  assert(bgp_peer != NULL);

  bgp_ctx = bgp_peer->main_ctx;
  caller_ctx =
    (bgp_peer->caller_ctx) ? bgp_peer->caller_ctx : bgp_ctx->caller_ctx;

  if (!msg_is_sane(bgp_ctx, buf, buf_len))
    {
      return;
    }
  msg_len = ntohs(msg->hdr.length);
  DBG_PEER(bgp_ctx, bgp_peer, "Received %u byte %s message", msg_len,
           msg_type_to_str((enum bgp_msg_type)msg->hdr.type));

  switch (msg->hdr.type)
    {
    case BGP_MSG_OPEN:
      msg->msg.open.as_num = ntohs(msg->msg.open.as_num);
      msg->msg.open.bgp_id = ntohl(msg->msg.open.bgp_id);
      if (bgp_peer->flags.opened)
        {
          ERR_PEER(bgp_ctx, bgp_peer, "Received open after an already "
                   "succesfull previous open");
        }
      bgp_peer->flags.opened = true;
      bgp_peer->id.as_num = msg->msg.open.as_num;
      bgp_peer->id.bgp_id = msg->msg.open.bgp_id;
      bgp_peer->id.version = msg->msg.open.version;
      if (bgp_ctx->cbs.open_cb)
        {
          sukat_sock_event_t event =
            (bgp_peer->flags.accepted_from_server_socket) ?
            SUKAT_SOCK_CONN_EVENT_ACCEPTED : SUKAT_SOCK_CONN_EVENT_CONNECT;
          void *new_caller_ctx =
            bgp_ctx->cbs.open_cb(caller_ctx, bgp_peer, &bgp_peer->id, event);

          if (new_caller_ctx)
            {
              bgp_peer->caller_ctx = new_caller_ctx;
            }
          // RFC says to reply to the open with a KEEPALIVE
          if (!destro_is_deleted(bgp_ctx->destro_ctx,
                                 &bgp_peer->destro_client_ctx))
            {
              if (msg_send_keepalive(bgp_ctx, bgp_peer) != SUKAT_SEND_OK)
                {
                  ERR_PEER(bgp_ctx, bgp_peer,
                           "Failed to send KEEPALIVE after open");
                  destro_delete(bgp_ctx->destro_ctx,
                                &bgp_peer->destro_client_ctx);
                }
            }
        }
      break;
    case BGP_MSG_KEEPALIVE:
      if (bgp_ctx->cbs.keepalive_cb)
        {
          bgp_ctx->cbs.keepalive_cb(caller_ctx, bgp_peer, &bgp_peer->id);
        }
      break;
    case BGP_MSG_NOTIFICATION:
      if (bgp_ctx->cbs.notification_cb)
        {
          size_t data_len =
            msg_len - (sizeof(msg->hdr) + sizeof(msg->msg.notification));
          uint8_t *data = (data_len) ? msg->msg.notification.data : NULL;

          bgp_ctx->cbs.notification_cb(caller_ctx, bgp_peer,
                                       msg->msg.notification.error,
                                       msg->msg.notification.error_subcode,
                                       data, data_len);
        }
      else
        {
          ERR_PEER(bgp_ctx, bgp_peer, "Received notification with code %hu "
                   "subcode %hu but no notification_cb registered",
                   msg->msg.notification.error,
                   msg->msg.notification.error_subcode);
        }
      break;
    default:
      ERR_PEER(bgp_ctx, bgp_peer, "Unknown message type %u received",
               msg->hdr.type);
      break;
    }
}

static size_t msg_len_open(sukat_bgp_t *ctx)
{
  (void)ctx;
  // Add optional parameter lengths here when added
  return sizeof(struct bgp_hdr) + sizeof(struct bgp_open);
}

static bool msg_send_open(sukat_bgp_t *ctx, sukat_bgp_peer_t *peer)
{
  size_t msg_len = msg_len_open(ctx);
  uint8_t buf[msg_len];
  struct bgp_msg *msg = (struct bgp_msg *)buf;

  assert(ctx != NULL && peer != NULL);

  // Fill header.
  msg_header_fill(msg, BGP_MSG_OPEN, msg_len);
  msg->hdr.type = BGP_MSG_OPEN;

  memset(&msg->msg.open, 0, sizeof(msg->msg.open));

  // Fill message.
  msg->msg.open.as_num = htons(ctx->id.as_num);
  msg->msg.open.version = BGP_VERSION;
  msg->msg.open.bgp_id = htonl(ctx->id.bgp_id);
  msg->msg.open.hold_time = htons(ctx->hold_time);
  // Add optional parameters here when added.
  msg->msg.open.opt_param_len = 0;

  if (sukat_send_msg(ctx->sock_ctx, peer->sock_peer,
                     buf, msg_len) == SUKAT_SEND_OK)
    {
      LOG(ctx, "Sent open message to peer");
      return true;
    }

  return false;
}

static void *bgp_conn_cb(void *caller_ctx, sukat_sock_endpoint_t *sock_peer,
                         struct sockaddr_storage *sockaddr, size_t sock_len,
                         sukat_sock_event_t event)
{
  sukat_bgp_peer_t *bgp_peer;
  sukat_bgp_t *ctx;
  void *bgp_caller_ctx = NULL;
  void *retval = NULL;

  if (event == SUKAT_SOCK_CONN_EVENT_DISCONNECT)
    {
      bgp_peer = (sukat_bgp_peer_t *)caller_ctx;
      ctx = bgp_peer->main_ctx;
      bgp_caller_ctx =
        (bgp_peer->caller_ctx) ? bgp_peer->caller_ctx : ctx->caller_ctx;

      // TODO use some bgp_peer_stringify here.
      LOG(ctx, "BGP client disconnected");
      if (ctx->cbs.open_cb)
        {
          ctx->cbs.open_cb(bgp_caller_ctx, bgp_peer, &bgp_peer->id, event);
        }
      free(bgp_peer);

      return NULL;
    }
  if (event == SUKAT_SOCK_CONN_EVENT_ACCEPTED)
    {
      char peer_buf[INET6_ADDRSTRLEN];
      ctx = (sukat_bgp_t *)caller_ctx;

      LOG(ctx, "New BGP %s from %s",
          (sock_peer) ? "client" : "server connection",
          sukat_sock_stringify_peer(sockaddr, sock_len, peer_buf,
                                    sizeof(peer_buf)));

      bgp_peer = (sukat_bgp_peer_t *)calloc(1, sizeof(*bgp_peer));
      if (!bgp_peer)
        {
          ERR(ctx, "Out of memory for new BGP peer");
          sukat_sock_disconnect(ctx->sock_ctx, sock_peer);
          return NULL;
        }
      bgp_peer->main_ctx = ctx;
      bgp_peer->sock_peer = sock_peer;
      bgp_peer->flags.accepted_from_server_socket = true;
      retval = (void *)bgp_peer;
    }
  else
    {
      bgp_peer = (sukat_bgp_peer_t *)caller_ctx;
      ctx = bgp_peer->main_ctx;
    }
  if (msg_send_open(ctx, bgp_peer) == true)
    {
      DBG(ctx, "Sent open to new peer");
      return retval;
    }
  sukat_sock_disconnect(ctx->sock_ctx, sock_peer);
  return NULL;
}

void bgp_destro_close(void *main_ctx, void *client_ctx)
{
  sukat_bgp_t *ctx = (sukat_bgp_t *)main_ctx;

  if (client_ctx)
    {
      sukat_bgp_peer_t *bgp_peer = (sukat_bgp_peer_t *)client_ctx;
      void *caller_ctx = (bgp_peer->caller_ctx) ? bgp_peer->caller_ctx :
        ctx->caller_ctx;

      sukat_sock_disconnect(ctx->sock_ctx, bgp_peer->sock_peer);
      if (!bgp_peer->flags.destroyed && ctx->cbs.open_cb)
        {
          ctx->cbs.open_cb(caller_ctx, bgp_peer, &bgp_peer->id,
                           SUKAT_SOCK_CONN_EVENT_DISCONNECT);
        }
    }
  else
    {
      sukat_sock_disconnect(ctx->sock_ctx, ctx->endpoint);
      sukat_sock_destroy(ctx->sock_ctx);
    }
}

void fill_endpoint_values(struct sukat_sock_endpoint_params *eparams,
                          struct sukat_sock_params_inet *pinet)
{
  const char *bgp_port = "179";
  const char *bind_to = "127.0.0.1";

  assert(eparams != NULL && pinet != NULL);
  eparams->pinet.ip = (pinet->ip) ? pinet->ip : bind_to;
  eparams->pinet.port = (pinet->port) ? pinet->port : bgp_port;
  eparams->domain = AF_UNSPEC;
  eparams->type = SOCK_STREAM;
}

sukat_bgp_t *sukat_bgp_create(struct sukat_bgp_params *params,
                              struct sukat_bgp_cbs *cbs)
{
  sukat_bgp_t *ctx;

  if (!params)
    {
      return NULL;
    }
  ctx = (sukat_bgp_t *)calloc(1, sizeof(*ctx));
  if (ctx)
    {
      struct sukat_sock_params sock_params = { };
      struct sukat_sock_cbs sock_cbs = { };

      ctx->caller_ctx = params->caller_ctx;
      if (cbs)
        {
          memcpy(&ctx->cbs, cbs, sizeof(ctx->cbs));
        }
      memcpy(&ctx->id, &params->id, sizeof(ctx->id));
      memcpy(&ctx->cbs, cbs, sizeof(ctx->cbs));

      sock_cbs.msg_len_cb = bgp_msg_len_cb;
      sock_cbs.msg_cb = bgp_msg_cb;
      sock_cbs.conn_cb = bgp_conn_cb;
      sock_cbs.log_cb = ctx->cbs.log_cb;
      sock_params.caller_ctx = (void *)ctx;
      sock_params.master_epoll_fd = params->master_epoll_fd;
      sock_params.master_epoll_fd_set = params->master_epoll_set;

      ctx->sock_ctx = sukat_sock_create(&sock_params, &sock_cbs);
      if (ctx->sock_ctx)
        {
          struct destro_cbs dcbs = { };
          struct destro_params dparams = { };

          dparams.main_ctx = (void *)ctx;
          dcbs.log_cb = (cbs) ? cbs->log_cb : NULL;
          dcbs.close = bgp_destro_close;

          ctx->destro_ctx = destro_create(&dparams, &dcbs);
          if (ctx->destro_ctx)
            {
              struct sukat_sock_endpoint_params eparams = { };

              fill_endpoint_values(&eparams, &params->pinet);
              eparams.server = true;
              ctx->endpoint =
                sukat_sock_endpoint_add(ctx->sock_ctx, &eparams);
              if (ctx->endpoint)
                {
                  LOG(ctx, "Created bgp context");
                  return ctx;
                }
              free(ctx->destro_ctx);
            }
          sukat_sock_destroy(ctx->sock_ctx);
        }
      free(ctx);
    }
  return NULL;
}

int sukat_bgp_read(sukat_bgp_t *ctx, int timeout)
{
  int ret;

  destro_cb_enter(ctx->destro_ctx);
  ret = sukat_sock_read(ctx->sock_ctx, timeout);
  destro_cb_exit(ctx->destro_ctx);

  return ret;
};

sukat_bgp_peer_t *sukat_bgp_peer_add(sukat_bgp_t *ctx,
                                     struct sukat_sock_params_inet *pinet)
{
  if (ctx)
    {
      if (pinet)
        {
          sukat_bgp_peer_t *peer_ctx;

          peer_ctx = (sukat_bgp_peer_t *)calloc(1, sizeof(*peer_ctx));
          if (peer_ctx)
            {
              struct sukat_sock_endpoint_params eparams = { };

              fill_endpoint_values(&eparams, pinet);
              peer_ctx->main_ctx = ctx;
              eparams.caller_ctx = (void *)peer_ctx;
              peer_ctx->sock_peer =
                sukat_sock_endpoint_add(ctx->sock_ctx, &eparams);
              if (peer_ctx->sock_peer)
                {
                  LOG(ctx, "Added peer %s:%s", pinet->ip, pinet->port);
                  return peer_ctx;
                }
              free(peer_ctx);
            }
          else
            {
              ERR(ctx, "Out of memory for BGP peer: %s", strerror(errno));
            }
        }
      else
        {
          ERR(ctx, "No peer identified for BGP");
        }
    }
  return NULL;
};

static size_t bgp_notification_length(size_t data_len)
{
  struct bgp_msg *msg;
  return sizeof(msg->hdr) + sizeof(msg->msg.notification) + data_len;
}

enum sukat_sock_send_return sukat_bgp_send_notification(sukat_bgp_t *bgp_ctx,
                                                        sukat_bgp_peer_t *peer,
                                                        uint8_t error_code,
                                                        uint8_t error_subcode,
                                                        uint8_t *data,
                                                        size_t data_len)
{
  size_t msg_len = bgp_notification_length(data_len);
  uint8_t buf[msg_len];
  struct bgp_msg *msg = (struct bgp_msg *)buf;

  msg_header_fill(msg, BGP_MSG_NOTIFICATION, msg_len);
  msg->msg.notification.error = error_code;
  msg->msg.notification.error_subcode = error_subcode;
  memcpy(msg->msg.notification.data, data, data_len);

  return sukat_send_msg(bgp_ctx->sock_ctx, peer->sock_peer, buf, msg_len);
}

void sukat_bgp_destroy(sukat_bgp_t *ctx)
{
  if (ctx)
    {
      destro_delete(ctx->destro_ctx, NULL);
    }
}

void sukat_bgp_disconnect(sukat_bgp_t *ctx, sukat_bgp_peer_t *bgp_peer)
{
  if (ctx && bgp_peer)
    {
      bgp_peer->flags.destroyed = true;
      destro_delete(ctx->destro_ctx, &bgp_peer->destro_client_ctx);
    }
}

/*! @} */
