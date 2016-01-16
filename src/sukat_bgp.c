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
#define BGP_MAX_LEN 4096

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
  uint8_t marker[16]; //!< All ones always.
  uint16_t length; //!< Length in octets.
  uint8_t type; //!< \ref bgp_msg_type.
};

/*!
 * The path_attr header as seen on the wire.
 */
struct bgp_path_attr
{
  struct sukat_bgp_attr_flags flags;
  uint8_t type; //!< Matches ::sukat_bgp_attr_t
};

/*!
 * The AS_PATh path attribute as seen on the wire.
 */
struct bgp_as_path_network
{
  uint8_t type; //!< \ref sukat_bgp_as_path_type.
  uint8_t number_of_as_numbers; //!< Number, not bytes. so bytes == 2*numbers.
  uint16_t as_numbers[];
};

/*!
 * The BGP open message as seen on the wire.
 */
struct bgp_open
{
  uint8_t version;
  uint16_t as_num;
  uint16_t hold_time;
  uint32_t bgp_id;
  uint8_t opt_param_len;
  uint8_t opt_param[];
};

/*!
 * The BGP Notification message as seen on the wire
 */
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
      uint8_t update[0]; /*!< As this has three variable length fields,
                            it can't be easily added here as struct. */
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

static size_t bgp_msg_static_len(enum sukat_bgp_attr_type type,
                                 size_t n_entries)
{
  size_t ret;

  switch (type)
    {
    case SUKAT_BGP_ATTR_ORIGIN:
      ret = 1;
      break;
    case SUKAT_BGP_ATTR_AS_PATH:
      ret = sizeof(*(struct bgp_as_path_network *)NULL) + n_entries *
        sizeof(*((struct bgp_as_path_network *)NULL)->as_numbers);
      break;
    case SUKAT_BGP_ATTR_NEXT_HOP:
    case SUKAT_BGP_ATTR_MULTI_EXIT_DISC:
    case SUKAT_BGP_ATTR_LOCAL_PREF:
      ret = sizeof(uint32_t);
      break;
    case SUKAT_BGP_ATTR_ATOMIC_AGGREGATE:
      ret = 0;
      break;
    case SUKAT_BGP_ATTR_AGGREGATOR:
      ret = sizeof(*(struct sukat_bgp_aggregator *)NULL);
      break;
    default:
      ret = 0;
      break;
    }

  return ret;
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
          if (msg_len >= sizeof(msg->hdr) && msg_len <= BGP_MAX_LEN)
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
                  if (msg_len == 19)
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
                case BGP_MSG_UPDATE:
                  if (msg_len >= sizeof(msg->hdr) + 4)
                    {
                      return true;
                    }
                  else
                    {
                      ERR(bgp_ctx, "Too short (%hu) message for update",
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

enum sukat_sock_send_return sukat_bgp_send_keepalive(sukat_bgp_t *bgp_ctx,
                                                     sukat_bgp_peer_t *peer)
{
  struct bgp_msg msg = { };
  size_t msg_len = sizeof(msg.hdr);

  if (!bgp_ctx || !peer)
    {
      ERR(bgp_ctx, "No %s given to keepalive", (!peer) ? "peer" : "context");
      return SUKAT_SEND_ERROR;
    }
  msg_header_fill(&msg, BGP_MSG_KEEPALIVE, msg_len);
  DBG_PEER(bgp_ctx, peer, "Sending KEEPALIVE");

  return sukat_send_msg(bgp_ctx->sock_ctx, peer->sock_peer, (uint8_t *)&msg,
                        msg_len);
}

static int bgp_attr_get_extra_length_and_check(struct bgp_path_attr *head,
                                               uint8_t *payload,
                                               size_t left_in_payload)
{
  size_t static_length =
    bgp_msg_static_len((enum sukat_bgp_attr_type)head->type, 0);

  if (left_in_payload >= static_length)
    {
      if (head->type == SUKAT_BGP_ATTR_AS_PATH)
        {
          struct bgp_as_path_network *as_path =
            (struct bgp_as_path_network *)payload;

          static_length =
            bgp_msg_static_len((enum sukat_bgp_attr_type)head->type,
                               as_path->number_of_as_numbers);
          if (static_length > left_in_payload)
            {
              return -1;
            }
        }
      // Success.
      return (int)static_length;
    }
  return -1;
}

/*!
 * @brief Formats the path attributes to easies host byte order struct.
 *
 * @param bgp_ctx       BGP context, for error messages
 * @param data          Pointer to start of path attributes.
 * @param data_len      Length of path attributes
 *
 * @return != NULL      List of path attributes.
 * @return NULL         Failure.
 */
static struct sukat_bgp_path_attr *
  msg_update_process_attrs(sukat_bgp_t *bgp_ctx, uint8_t *data, size_t data_len)
{
  struct sukat_bgp_path_attr *attr_root = NULL, *attr_tail = NULL;
  uint8_t *ptr = data;
#define N_LEFT (data_len - (ptr - data))

  assert(bgp_ctx != NULL && data != NULL && data_len > 0);
  while (N_LEFT > 0)
    {
      struct bgp_path_attr *attr_head = (struct bgp_path_attr *)ptr;
      struct sukat_bgp_path_attr *new_attr = NULL;
      int extra_increment;
      struct sukat_bgp_as_path *path;
      size_t i;
      union
        {
          uint8_t *ptr;
          struct bgp_as_path_network *path;
          struct sukat_bgp_aggregator *aggregator;
          uint32_t *val32;
        } payload;

      if (N_LEFT < sizeof(*attr_head))
        {
          ERR(bgp_ctx, "Only %u bytes left when needing %u bytes for type and "
              "flags", N_LEFT, sizeof(*attr_head));
          goto fail;
        }
      ptr += sizeof(*attr_head);

      extra_increment = bgp_attr_get_extra_length_and_check(attr_head,
                                                            ptr,
                                                            N_LEFT);
      if (extra_increment < 0)
        {
          ERR(bgp_ctx, "Not enough data for left (%u) in message for type %hhu",
              N_LEFT, attr_head->type);
          goto fail;
        }
      new_attr = (struct sukat_bgp_path_attr *)calloc(1, sizeof(*new_attr) +
                                                      extra_increment);
      if (!new_attr)
        {
          ERR(bgp_ctx, "Couldn't allocate memory for new path attribute: %s",
              strerror(errno));
          goto fail;
        }

      // Copy and typecast values common to all
      new_attr->flags = attr_head->flags;
      new_attr->attr_type = (sukat_bgp_attr_t)attr_head->type;
      payload.ptr = ptr;
      ptr += extra_increment;

      switch (attr_head->type)
        {
        case SUKAT_BGP_ATTR_ORIGIN:
          new_attr->value.origin = *payload.ptr;
          break;
        case SUKAT_BGP_ATTR_AS_PATH:
          path = &new_attr->value.as_path;

          path->type = (enum sukat_bgp_as_path_type)payload.path->type;
          path->number_of_as_numbers = payload.path->number_of_as_numbers;
          for (i = 0; i < path->number_of_as_numbers; i++)
            {
              path->as_numbers[i] = ntohs(payload.path->as_numbers[i]);
            }
          break;
        case SUKAT_BGP_ATTR_NEXT_HOP:
        case SUKAT_BGP_ATTR_MULTI_EXIT_DISC:
        case SUKAT_BGP_ATTR_LOCAL_PREF:
          new_attr->value.next_hop = ntohl(*payload.val32);
          break;
        case SUKAT_BGP_ATTR_AGGREGATOR:
          new_attr->value.aggregator.as_number =
            ntohs(payload.aggregator->as_number);
          new_attr->value.aggregator.ip = ntohs(payload.aggregator->ip);
          break;
        case SUKAT_BGP_ATTR_ATOMIC_AGGREGATE:
          // Length 0 attribute.
          break;
        default:
          ERR(bgp_ctx, "Unknown type %hhu", attr_head->type);
          goto fail;
          break;
        }

      // Add to list of attrs.
      if (!attr_root)
        {
          assert(!attr_tail);
          attr_root = attr_tail = new_attr;
        }
      else
        {
          assert(attr_tail != NULL);
          attr_tail->next = new_attr;
          attr_tail = new_attr;
        }
    }

  return attr_root;

fail:
  sukat_bgp_free_attr_list(attr_root);
  return NULL;
#undef N_LEFT
}

static bool msg_update_process(sukat_bgp_t *bgp_ctx, struct bgp_msg *msg,
                               struct sukat_bgp_update *update)
{
  uint16_t val16;
  uint8_t *ptr;
  // Length left for variable length values.
#define MSG_LEFT (msg->hdr.length - (ptr - (uint8_t *)msg))

  assert(bgp_ctx != NULL && msg != NULL && update != NULL);

  ptr = msg->msg.update;
  val16 = ntohs(*(uint16_t *)ptr);
  ptr += sizeof(uint16_t);
  if (val16 > 0)
    {
      DBG(bgp_ctx, "Update message has %hu bytes of withdrawn data",
          val16);
      if (MSG_LEFT < val16)
        {
          ERR(bgp_ctx, "Message claims to have %hu data when only %u bytes "
              "readable", val16, MSG_LEFT);
          goto fail;
        }
      update->withdrawn_length = val16;
      update->withdrawn = (struct sukat_bgp_lp*)ptr;
      ptr += val16;
    }
  val16 = ntohs(*(uint16_t *)ptr);
  ptr += sizeof(uint16_t);
  if (val16)
    {
      DBG(bgp_ctx, "Update message has %hu bytes of path attributes", val16);
      if (MSG_LEFT < val16)
        {
          ERR(bgp_ctx, "Message claims to have %hu data when only %u bytes "
              "readable", val16, MSG_LEFT);
          goto fail;
        }
      update->path_attr = msg_update_process_attrs(bgp_ctx, ptr, val16);
      if (!update->path_attr)
        {
          goto fail;
        }
      ptr += val16;
    }
  if (MSG_LEFT)
    {
      DBG(bgp_ctx, "Update message has %u bytes of reachability", MSG_LEFT);
      update->reachability_length = MSG_LEFT;
      update->reachability = (struct sukat_bgp_lp *)ptr;
    }

  return true;
fail:
  sukat_bgp_free_attr_list(update->path_attr);
  return false;
}

static void bgp_msg_cb(void *ctx,
                       __attribute__((unused)) sukat_sock_endpoint_t *client,
                       uint8_t *buf, size_t buf_len)
{
  struct bgp_msg *msg = (struct bgp_msg *)buf;
  sukat_bgp_peer_t *bgp_peer = (sukat_bgp_peer_t *)ctx;
  sukat_bgp_t *bgp_ctx;
  struct sukat_bgp_update update = { };
  void *caller_ctx;

  assert(bgp_peer != NULL);

  bgp_ctx = bgp_peer->main_ctx;
  caller_ctx =
    (bgp_peer->caller_ctx) ? bgp_peer->caller_ctx : bgp_ctx->caller_ctx;

  assert(bgp_ctx != NULL);

  if (!msg_is_sane(bgp_ctx, buf, buf_len))
    {
      return;
    }
  msg->hdr.length = ntohs(msg->hdr.length);
  DBG_PEER(bgp_ctx, bgp_peer, "Received %u byte %s message", msg->hdr.length,
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
              if (sukat_bgp_send_keepalive(bgp_ctx, bgp_peer) != SUKAT_SEND_OK)
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
            msg->hdr.length -
            (sizeof(msg->hdr) + sizeof(msg->msg.notification));
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
    case BGP_MSG_UPDATE:
      if (msg_update_process(bgp_ctx, msg, &update) == true)
        {
          if (bgp_ctx->cbs.update_cb)
            {
              bgp_ctx->cbs.update_cb(caller_ctx, bgp_peer, &bgp_peer->id,
                                     &update);
            }
          sukat_bgp_free_attr_list(update.path_attr);
        }
      else
        {
          ERR_PEER(bgp_ctx, bgp_peer, "Failed to process update");
        }
      break;;
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

      assert(ctx != NULL);

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

      assert(ctx != NULL);
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
      assert(ctx != NULL && bgp_peer != NULL);
    }
  if (msg_send_open(ctx, bgp_peer) == true)
    {
      DBG(ctx, "Sent open to new peer");
      return retval;
    }
  free(retval);
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

  assert(eparams != NULL && pinet != NULL);
  eparams->pinet.ip = (pinet->ip) ? pinet->ip : NULL;
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

  if (!ctx)
    {
      errno = EINVAL;
      return -1;
    }
  DBG(ctx, "Checking BGP ctx %p for data", ctx);
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

static int msg_fill_attrs(struct sukat_bgp_path_attr *attr, uint8_t *buf,
                          size_t buf_left)
{
  uint8_t *ptr = buf;
#define BUF_USED (ptr - buf)

  while (attr)
    {
      struct bgp_path_attr *head = (struct bgp_path_attr *)ptr;
      size_t i, next_item_len;
      union
        {
          uint8_t *ptr;
          struct bgp_as_path_network *path;
          struct sukat_bgp_aggregator *aggregator;
          uint32_t *val32;
        } payload;

      next_item_len = sizeof(*head) +
        bgp_msg_static_len(attr->attr_type,
                           (attr->attr_type == SUKAT_BGP_ATTR_AS_PATH) ?
                           attr->value.as_path.number_of_as_numbers : 0);
      if (BUF_USED + next_item_len > buf_left)
        {
          return -1;
        }

      head->flags = attr->flags;
      head->type = (uint8_t )attr->attr_type;
      payload.ptr = ptr + sizeof(*head);
      switch (attr->attr_type)
        {
        case SUKAT_BGP_ATTR_ORIGIN:
          *payload.ptr = attr->value.origin;
          break;
        case SUKAT_BGP_ATTR_AS_PATH:
          payload.path->type = (uint8_t)attr->value.as_path.type;
          payload.path->number_of_as_numbers =
            attr->value.as_path.number_of_as_numbers;
          for (i = 0; i < attr->value.as_path.number_of_as_numbers; i++)
            {
              payload.path->as_numbers[i] =
                htons(attr->value.as_path.as_numbers[i]);
            }
          break;
        case SUKAT_BGP_ATTR_NEXT_HOP:
        case SUKAT_BGP_ATTR_MULTI_EXIT_DISC:
        case SUKAT_BGP_ATTR_LOCAL_PREF:
          *payload.val32 = htonl(attr->value.next_hop);
        case SUKAT_BGP_ATTR_ATOMIC_AGGREGATE:
          break;
        case SUKAT_BGP_ATTR_AGGREGATOR:
          payload.aggregator->ip = htonl(attr->value.aggregator.ip);
          payload.aggregator->as_number =
            htons(attr->value.aggregator.as_number);
          break;
        default:
          abort();
          break;
        }

      attr = attr->next;
      ptr += next_item_len;
    }

  return BUF_USED;
}

static bool bgp_update_form(struct sukat_bgp_update *update, uint8_t *buf,
                            size_t buf_len)
{
  uint8_t *ptr;
  struct bgp_msg *msg = (struct bgp_msg *)buf;
#define BUF_USED (ptr - buf)
#define BUF_LEFT (buf_len - BUF_USED)

  // Check minimun required
  if (buf_len < sizeof(msg->hdr) + 2 * sizeof(uint16_t))
    {
      return false;
    }

  // Fill header when we know length.
  ptr = buf + sizeof(msg->hdr);
  *((uint16_t *)ptr) = htons(update->withdrawn_length);
  ptr += sizeof(uint16_t);

  if (update->withdrawn_length <= BUF_LEFT)
    {
      uint16_t *attr_length_val;
      int used_in_attrs;

      if (update->withdrawn_length > 0)
        {
          memcpy(ptr, update->withdrawn, update->withdrawn_length);
        }
      ptr += update->withdrawn_length;
      attr_length_val = (uint16_t *)ptr;
      ptr += sizeof(uint16_t);
      used_in_attrs =
        msg_fill_attrs(update->path_attr, ptr, BUF_LEFT);
      if (used_in_attrs >= 0)
        {
          *attr_length_val = htons(used_in_attrs);
          ptr += used_in_attrs;

          if (BUF_LEFT >= update->reachability_length)
            {
              if (update->reachability_length)
                {
                  memcpy(ptr, update->reachability,
                         update->reachability_length);
                }
              ptr += update->reachability_length;

              // Fill header at last.
              msg_header_fill(msg, BGP_MSG_UPDATE, BUF_USED);
              return true;
            }
        }
    }
  return false;
#undef BUF_USED
#undef BUF_LEFT
}

enum sukat_sock_send_return
sukat_bgp_send_update(sukat_bgp_t *bgp_ctx, sukat_bgp_peer_t *peer,
                      struct sukat_bgp_update *update)
{
  if (bgp_ctx && peer && update)
    {
      uint8_t buf[BGP_MAX_LEN];

      if (bgp_update_form(update, buf, sizeof(buf)) == true)
        {
          struct bgp_msg *msg = (struct bgp_msg *)buf;

          LOG_PEER(bgp_ctx, peer, "Sending %u byte update message",
                   ntohs(msg->hdr.length));

          return sukat_send_msg(bgp_ctx->sock_ctx, peer->sock_peer,
                                buf, ntohs(msg->hdr.length));
        }
      ERR(bgp_ctx, "Update message requested for sending too larger for BGP "
          "maximum length (%u)", BGP_MAX_LEN);
    }
  else
    {
      ERR(bgp_ctx, "Invalid NULL argument: ctx %p, peer %p, update %p",
          bgp_ctx, peer, update);
    }

  return SUKAT_SEND_ERROR;
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

void sukat_bgp_free_attr_list(struct sukat_bgp_path_attr *attr_list)
{
  while (attr_list)
    {
      struct sukat_bgp_path_attr *iter = attr_list;;

      attr_list = attr_list->next;
      free(iter);
    }
}

/*! @} */
