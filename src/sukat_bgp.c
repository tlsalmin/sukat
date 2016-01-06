/*!
 * @file sukat_bgp.h
 * @brief BGP library implementation.
 *
 * @addtogroup sukat_bgp
 * @{
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "sukat_bgp.h"
#include "sukat_log_internal.h"
#include "sukat_sock.h"
#include "delayed_destruction.h"

struct sukat_bgp_ctx_t
{
  struct sukat_bgp_cbs cbs;
  sukat_sock_t *sock_ctx;
  void *caller_ctx;
  struct {
      uint8_t open_sent:1; //!< True if we have received a BGP_MSG_OPEN.
      uint8_t opened:1; //!< True if we have received a BGP_MSG_OPEN.
      uint8_t server:1; //!< True if we're a server.
      uint8_t unused:5;
  } flags;
  destro_t *destro_ctx;
  uint16_t hold_time;
  uint16_t my_as;
  uint32_t bgp_id;
};

struct sukat_bgp_client_ctx
{
  destro_client_t destro_client_ctx;
  sukat_sock_endpoint_t *sock_peer;
  struct {
      uint8_t opened:1; //!< True if we have received a BGP_MSG_OPEN.
      uint8_t unused:7;
  } flags;
  uint16_t as;
  uint32_t bgp_id;
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

struct bgp_open
{
  uint8_t version;
  uint16_t my_as;
  uint16_t hold_time;
  uint32_t bgp_id;
  uint8_t opt_param_len;
  uint8_t opt_param[];
};

struct bgp_msg
{
  struct bgp_hdr hdr;
  union
    {
      struct bgp_open open;
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

static bool msg_is_sane(uint8_t *buf, size_t buf_len)
{
  struct bgp_msg *msg = (struct bgp_msg *)buf;

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
                  return (buf_len == sizeof(msg->hdr) + sizeof(msg->msg.open) +
                          msg->msg.open.opt_param_len);
                  break;
                default:
                  break;
                }
            }
        }
    }
  return false;
}

static void bgp_msg_cb(void *ctx, sukat_sock_endpoint_t *client, uint8_t *buf,
                       size_t buf_len)
{
  struct bgp_msg *msg = (struct bgp_msg *)buf;
  sukat_bgp_client_t *bgp_client = (client) ? (sukat_bgp_client_t *)ctx : NULL;
  sukat_bgp_t *bgp_ctx = (bgp_client) ? bgp_client->main_ctx :
    (sukat_bgp_t *)ctx;
  void *caller_ctx = (bgp_client && bgp_client->caller_ctx) ?
    bgp_client->caller_ctx : bgp_ctx->caller_ctx;

  if (!msg_is_sane(buf, buf_len))
    {
      ERR(bgp_ctx, "Message type %s length %u wasn't sane",
          msg_type_to_str((enum bgp_msg_type)msg->hdr.type), buf_len);
      return;
    }
  DBG(bgp_ctx, "Received %u byte %s message", buf_len,
      msg_type_to_str((enum bgp_msg_type)msg->hdr.type));

  switch (msg->hdr.type)
    {
    case BGP_MSG_OPEN:
      msg->msg.open.my_as = ntohs(msg->msg.open.my_as);
      msg->msg.open.bgp_id = ntohl(msg->msg.open.bgp_id);
      if ((bgp_client && bgp_client->flags.opened) ||
          (!bgp_client && bgp_ctx->flags.opened))
        {
          ERR(bgp_ctx, "%s sent duplicate open message",
              (bgp_client) ?  "Client" : "Server");
        }
      if (bgp_ctx->cbs.open_cb)
        {
          void *new_caller_ctx =
            bgp_ctx->cbs.open_cb(caller_ctx, bgp_client, msg->msg.open.version,
                                 msg->msg.open.my_as, msg->msg.open.bgp_id);

          if (bgp_client && new_caller_ctx)
            {
              bgp_client->caller_ctx = new_caller_ctx;
            }
        }
      if (bgp_client)
        {
          bgp_client->flags.opened = true;
          bgp_client->as = msg->msg.open.my_as;
          bgp_client->bgp_id = msg->msg.open.bgp_id;
        }
      else
        {
          bgp_ctx->flags.opened = true;
        }
      break;
    default:
      ERR(bgp_ctx, "Unknown message type %u received", msg->hdr.type);
      break;
    }
}

static size_t msg_len_open(sukat_bgp_t *ctx)
{
  (void)ctx;
  // Add optional parameter lengths here when added
  return sizeof(struct bgp_hdr) + sizeof(struct bgp_open);
}

static bool msg_send_open(sukat_bgp_t *ctx, sukat_bgp_client_t *client)
{
  size_t msg_len = msg_len_open(ctx);
  uint8_t buf[msg_len];
  struct bgp_msg *msg = (struct bgp_msg *)buf;

  // Fill header.
  memset(&msg->hdr.marker, 1, sizeof(msg->hdr.marker));
  msg->hdr.length = htons(msg_len);
  msg->hdr.type = BGP_MSG_OPEN;
  memset(&msg->msg.open, 0, sizeof(msg->msg.open));

  // Fill message.
  msg->msg.open.my_as = htons(ctx->my_as);
  msg->msg.open.version = 4;
  msg->msg.open.bgp_id = htonl(ctx->bgp_id);
  msg->msg.open.hold_time = htons(ctx->hold_time);
  // Add optional parameters here when added.
  msg->msg.open.opt_param_len = 0;

  if (sukat_send_msg(ctx->sock_ctx, (client) ? client->sock_peer : NULL,
                     buf, msg_len) == SUKAT_SEND_OK)
    {
      LOG(ctx, "Sent open message to %s.", (client) ? "client" : "server");
      ctx->flags.open_sent = true;
      return true;
    }

  return false;
}

static void *bgp_conn_cb(void *caller_ctx, sukat_sock_endpoint_t *sock_peer,
                         struct sockaddr_storage *sockaddr, size_t sock_len,
                         bool disconnect)
{
  if (!disconnect)
    {
      sukat_bgp_t *ctx = (sukat_bgp_t *)caller_ctx;
      char peer_buf[INET6_ADDRSTRLEN];
      sukat_bgp_client_t *client;

      LOG(ctx, "New BGP %s from %s",
          (sock_peer) ? "client" : "server connection",
          sukat_sock_stringify_peer(sockaddr, sock_len, peer_buf,
                                    sizeof(peer_buf)));

      if (sock_peer)
        {
          client = (sukat_bgp_client_t *)calloc(1, sizeof(*client));
          if (client)
            {
              client->main_ctx = ctx;
              client->sock_peer = sock_peer;
              if (msg_send_open(ctx, client) == true)
                {
                  DBG(ctx, "Sent open to new client");
                  return (void *)client;
                }
              free(client);
            }
          else
            {
              ERR(ctx, "Out of memory for new BGP peer");
            }
          sukat_sock_disconnect(ctx->sock_ctx, sock_peer);
        }
      else
        {
          if (msg_send_open(ctx, NULL) == true)
            {
              LOG(ctx, "Sent open message to server");
              return NULL;
            }
          else
            {
              ERR(ctx, "Failed to send open message");
            }
          sukat_sock_destroy(ctx->sock_ctx);
          ctx->sock_ctx = NULL;
        }
    }
  else
    {
      sukat_bgp_client_t *client = (sukat_bgp_client_t *)caller_ctx;
      sukat_bgp_t *ctx = client->main_ctx;

      // TODO use some bgp_peer_stringify here.
      LOG(ctx, "BGP client disconnected");
      free(client);
    }
  return NULL;
}

void bgp_destro_close(void *main_ctx, void *client_ctx)
{
  sukat_bgp_t *ctx = (sukat_bgp_t *)main_ctx;

  if (client_ctx)
    {
      sukat_bgp_client_t *client = (sukat_bgp_client_t *)client_ctx;

      sukat_sock_disconnect(ctx->sock_ctx, client->sock_peer);
    }
  else
    {
      sukat_sock_destroy(ctx->sock_ctx);
    }
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
      const char *bgp_port = "179";
      const char *bind_to = "127.0.0.1";
      struct sukat_sock_params sock_params = { };
      struct sukat_sock_cbs sock_cbs = { };

      ctx->caller_ctx = params->caller_ctx;
      if (cbs)
        {
          ctx->cbs.log_cb = sock_cbs.log_cb = cbs->log_cb;
          ctx->cbs.open_cb = cbs->open_cb;
        }
      sock_cbs.msg_len_cb = bgp_msg_len_cb;
      sock_cbs.msg_cb = bgp_msg_cb;
      sock_cbs.conn_cb = bgp_conn_cb;

      sock_params.pinet.ip = (!params->ip && params->server) ? bind_to :
        params->ip;
      sock_params.pinet.port = (params->port) ? params->port : bgp_port;
      sock_params.domain = AF_UNSPEC;
      sock_params.type = SOCK_STREAM;
      sock_params.caller_ctx = (void *)ctx;
      ctx->flags.server = sock_params.server = params->server;
      if (cbs)
        {
          memcpy(&ctx->cbs, cbs, sizeof(ctx->cbs));
        }
      if (params)
        {
          ctx->my_as = params->my_as;
          ctx->bgp_id = params->bgp_id;
        }
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
              LOG(ctx, "Created bgp %s context",
                  (ctx->flags.server) ? "server" : "client");
              return ctx;
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

void sukat_bgp_destroy(sukat_bgp_t *ctx)
{
  if (ctx)
    {
      destro_delete(ctx->destro_ctx, NULL);
    }
}

void sukat_bgp_disconnect(sukat_bgp_t *ctx, sukat_bgp_client_t *client)
{
  if (ctx && client)
    {
      destro_delete(ctx->destro_ctx, &client->destro_client_ctx);
    }
}

/*! @} */
