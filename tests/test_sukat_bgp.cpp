#include <iostream>
#include <fstream>
#include <random>
#include <string>

#include "gtest/gtest.h"
#include "test_common.h"

extern "C"{
#include "sukat_log_internal.c"
#include "sukat_bgp.c"
#include "sukat_sock.h"
#include "sukat_util.h"
#include <stdlib.h>
#include <stdint.h>
}

class sukat_bgp_test : public ::testing::Test
{
protected:
  sukat_bgp_test() {
  }

  virtual ~sukat_bgp_test() {
  }

  virtual void SetUp() {
      memset(&default_params, 0, sizeof(default_params));
      memset(&default_cbs, 0, sizeof(default_cbs));
      default_params.pinet.port = random_port;
      default_cbs.log_cb = test_log_cb;
  }

  virtual void TearDown() {
  }

  struct sukat_bgp_params default_params;
  struct sukat_bgp_cbs default_cbs;
  const char *random_port = "0";
};

struct bgp_test_ctx
{
  struct {
      uint16_t open_should_visit:1;
      uint16_t open_visited:1;
      uint16_t disconnect_should:1;
      uint16_t keepalive_should:1;
      uint16_t keepalive_visited:1;
      uint16_t notification_should:1;
      uint16_t notification_visited:1;
      uint16_t update_should:1;

      uint16_t update_visited:1;
      uint16_t unused:7;
  };
  sukat_bgp_peer_t *newest_client;
  uint8_t match_version;
  uint16_t match_as_num;
  uint32_t match_bgp_id;
  uint8_t match_error;
  uint8_t match_error_sub;
  size_t data_len;
  uint8_t *data;
  struct sukat_bgp_update *match_update;
};

static void *open_cb(void *ctx, sukat_bgp_peer_t *peer,
                     sukat_sock_event_t event)
{
  struct bgp_test_ctx *tctx = (struct bgp_test_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  EXPECT_NE(nullptr, peer);
  if (tctx)
    {
      const bgp_id_t *id= sukat_bgp_get_bgp_id(peer);
      EXPECT_NE(nullptr, id);
      EXPECT_EQ(true, tctx->open_should_visit);
      tctx->open_visited = true;
      tctx->newest_client = peer;
      EXPECT_EQ(tctx->match_version, id->version);
      EXPECT_EQ(tctx->match_as_num, id->as_num);
      EXPECT_EQ(tctx->match_bgp_id, id->bgp_id);
      if (tctx->disconnect_should)
        {
          EXPECT_EQ(SUKAT_SOCK_CONN_EVENT_DISCONNECT, event);
        }
    }

  return NULL;
}

static void keepalive_cb(void *ctx, sukat_bgp_peer_t *peer)
{
  struct bgp_test_ctx *tctx = (struct bgp_test_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  EXPECT_NE(nullptr, peer);
  if (tctx)
    {
      const bgp_id_t *id= sukat_bgp_get_bgp_id(peer);
      EXPECT_NE(nullptr, id);
      EXPECT_EQ(true, tctx->keepalive_should);
      tctx->keepalive_visited = true;
      EXPECT_EQ(tctx->match_version, id->version);
      EXPECT_EQ(tctx->match_as_num, id->as_num);
      EXPECT_EQ(tctx->match_bgp_id, id->bgp_id);
    }
}

static void notification_cb(void *ctx,
                            __attribute__((unused)) sukat_bgp_peer_t *peer,
                            uint8_t error_code, uint8_t subcode, uint8_t *data,
                            size_t data_len)
{
  struct bgp_test_ctx *tctx = (struct bgp_test_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  EXPECT_NE(nullptr, peer);
  if (tctx)
    {
      EXPECT_EQ(true, tctx->notification_should);
      EXPECT_EQ(tctx->match_error, error_code);
      EXPECT_EQ(tctx->match_error_sub, subcode);
      EXPECT_EQ(tctx->data_len, data_len);
      if (data_len)
        {
          int val = memcmp(data, tctx->data, data_len);

          EXPECT_EQ(0, val);
        }
      tctx->notification_visited = true;
    }
}

static void update_cb(void *ctx, sukat_bgp_peer_t *peer,
                      struct sukat_bgp_update *update)
{
  struct bgp_test_ctx *tctx = (struct bgp_test_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  EXPECT_NE(nullptr, peer);
  if (tctx)
    {
      int cmpval;
      struct sukat_bgp_path_attr *attr, *attr_match;
      const bgp_id_t *id = sukat_bgp_get_bgp_id(peer);

      EXPECT_NE(nullptr, id);
      EXPECT_EQ(true, tctx->update_should);
      EXPECT_NE(nullptr, update);
      EXPECT_EQ(update->withdrawn_length, tctx->match_update->withdrawn_length);
      EXPECT_EQ(update->reachability_length,
                tctx->match_update->reachability_length);
      if (update->withdrawn_length)
        {
          cmpval = memcmp(update->withdrawn, tctx->match_update->withdrawn,
                          update->withdrawn_length);
          EXPECT_EQ(0, cmpval);
        }
      if (update->reachability_length)
        {
          cmpval = memcmp(update->reachability,
                          tctx->match_update->reachability,
                          update->reachability_length);
          EXPECT_EQ(0, cmpval);
        }
      attr = update->path_attr;
      attr_match = tctx->match_update->path_attr;
      while (attr)
        {
          EXPECT_EQ(attr->attr_type, attr_match->attr_type);
          cmpval = memcmp(&attr->flags, &attr_match->flags, sizeof(attr->flags));
          EXPECT_EQ(0, cmpval);
          attr = attr->next;
          // Matching the value: TODO: Make the func for each type length
          // Will crash if there are different number of attrs.
          attr_match = attr_match->next;
        }
      EXPECT_EQ(nullptr, attr_match);
    }
  tctx->update_visited = true;
};

TEST_F(sukat_bgp_test, sukat_bgp_test_init)
{
  sukat_bgp_t *peer1, *peer2;
  struct bgp_test_ctx tctx = { };
  const uint16_t peer1_as = 14, peer2_as = 15;
  const uint32_t peer1_bgp = 35, peer2_bgp = 36;
  const uint8_t error_code = 5, error_subcode = 15;
  char error_data[] = "Horrible happened";
  char portbuf[strlen("65535") + 1];
  sukat_bgp_peer_t *peer2_from_peer1, *peer1_from_peer2;
  uint16_t peer1_port;
  int err;
  enum sukat_sock_send_return send_ret;

  // Shouldn't work with NULL parameters
  peer1 = sukat_bgp_create(NULL, NULL);
  EXPECT_EQ(nullptr, peer1);

  default_params.id.as_num = peer1_as;
  default_params.id.bgp_id = peer1_bgp;
  default_params.caller_ctx = (void *)&tctx;
  default_params.pinet.port = portbuf;
  default_cbs.open_cb = open_cb;
  default_cbs.keepalive_cb = keepalive_cb;
  default_cbs.notification_cb = notification_cb;
  default_cbs.update_cb = update_cb;

  snprintf(portbuf, sizeof(portbuf), "0");

  peer1 = sukat_bgp_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, peer1);

  default_params.id.as_num = peer2_as;
  default_params.id.bgp_id = peer2_bgp;

  peer1_port = sukat_sock_get_port(peer1->endpoint);
  EXPECT_LT(0, peer1_port);

  peer2 = sukat_bgp_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, peer2);

  snprintf(portbuf, sizeof(portbuf), "%hu", peer1_port);
  peer1_from_peer2 =
    sukat_bgp_peer_add(peer2, &default_params.pinet, NULL, NULL);
  EXPECT_NE(nullptr, peer1_from_peer2);

  // Received on the peer1 side
  tctx.match_as_num = peer1_as;
  tctx.match_bgp_id = peer1_bgp;
  tctx.match_version = 4;
  tctx.open_should_visit = true;

  err = sukat_bgp_read(peer1, 100);
  EXPECT_EQ(0, err);

  err = sukat_bgp_read(peer2, 100);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.open_visited);
  tctx.open_visited = false;

  tctx.match_as_num = peer2_as;
  tctx.match_bgp_id = peer2_bgp;
  // Should also receive a keepalive here.
  tctx.keepalive_should = true;
  err = sukat_bgp_read(peer1, 100);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.open_visited);
  EXPECT_EQ(true, tctx.keepalive_visited);
  tctx.open_visited = tctx.keepalive_visited = tctx.open_should_visit =false;
  peer2_from_peer1 = tctx.newest_client;
  EXPECT_NE(nullptr, peer2_from_peer1);

  // Read keepalive on peer2.
  tctx.match_as_num = peer1_as;
  tctx.match_bgp_id = peer1_bgp;
  err = sukat_bgp_read(peer2, 100);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.keepalive_visited);
  tctx.keepalive_should = tctx.keepalive_visited = false;

  // Test some notifications.
  tctx.match_error = error_code;
  tctx.match_error_sub = error_subcode;
  tctx.data = (uint8_t *)error_data;
  tctx.data_len = strlen(error_data);

  send_ret = sukat_bgp_send_notification(peer2, peer1_from_peer2,
                                         error_code, error_subcode,
                                         tctx.data, strlen(error_data));
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.notification_should = true;
  err = sukat_bgp_read(peer1, 100);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.notification_visited);
  tctx.notification_should = tctx.notification_visited = false;

  // Im so lazy. I should make another test case but everything is nice here.
    {
      size_t i = 0;
      struct sukat_bgp_attr_flags def_flags = { };
      uint8_t withdrawn_buf[128];
      uint8_t reachability_buf[128];

      def_flags.optional = true;
      def_flags.partial = true;
      def_flags.unused = 2;

      // The fun stops here.
      struct sukat_bgp_path_attr attr_array[] =
        {
            {
              .next = NULL,
              .flags = def_flags,
              .attr_type = SUKAT_BGP_ATTR_ORIGIN,
              .value =
                {
                  .origin = 4,
                },
            },
            {
              .next = &attr_array[i++],
              .flags = def_flags,
              .attr_type = SUKAT_BGP_ATTR_ATOMIC_AGGREGATE,
              // Just set something. Length is zero.
              .value =
                {
                  .origin = 4,
                },
            },
            {
              .next = &attr_array[i++],
              .flags = def_flags,
              .attr_type = SUKAT_BGP_ATTR_NEXT_HOP,
              .value =
                {
                  .next_hop = UINT32_MAX - 1,
                }
            },
            {
              .next = &attr_array[i++],
              .flags = def_flags,
              .attr_type = SUKAT_BGP_ATTR_MULTI_EXIT_DISC,
              .value =
                {
                  .multi_exit_disc = UINT32_MAX - 2,
                }
            },
            {
              .next = &attr_array[i++],
              .flags = def_flags,
              .attr_type = SUKAT_BGP_ATTR_LOCAL_PREF,
              .value =
                {
                  .next_hop = UINT32_MAX - 3,
                }
            },
            {
              .next = &attr_array[i++],
              .flags = def_flags,
              .attr_type = SUKAT_BGP_ATTR_AGGREGATOR,
              .value =
                {
                  .aggregator =
                    {
                      .as_number = 45,
                      .ip = 9999,
                    },
                }
            },
        };
      // One more AS_PATH attribute, which is tricky.
      uint8_t as_path_buf[128];
      struct sukat_bgp_path_attr *root_atr =
        (struct sukat_bgp_path_attr *)as_path_buf;
      struct sukat_bgp_update update =
        {
          .withdrawn_length = sizeof(withdrawn_buf),
          .withdrawn = (struct sukat_bgp_lp *)withdrawn_buf,
          .path_attr = root_atr,
          .reachability_length = sizeof(reachability_buf),
          .reachability = (struct sukat_bgp_lp *)reachability_buf,
        };

      root_atr->attr_type = SUKAT_BGP_ATTR_AS_PATH;
      root_atr->next = &attr_array[i - 1];
      root_atr->flags = def_flags;
      root_atr->value.as_path.type = SUKAT_BGP_AS_SEQUENCE;
      root_atr->value.as_path.number_of_as_numbers = 3;

      root_atr->value.as_path.as_numbers[0] = 3;
      root_atr->value.as_path.as_numbers[1] = 4;
      root_atr->value.as_path.as_numbers[2] = 5;

      tctx.match_update = &update;
      memset(reachability_buf, 1, sizeof(reachability_buf));
      memset(withdrawn_buf, 2, sizeof(withdrawn_buf));

        {
          uint8_t msg_buf[BGP_MAX_LEN];
          struct bgp_msg *msg  = (struct bgp_msg *)msg_buf;
          bool bret;
          uint8_t *ptr;
          int memval;
          uint16_t length, val16;
          uint32_t val32;
          struct sukat_bgp_path_attr *attr;
          // Check that it gets formatted correctly.

          // First check that it stops on too small buffer.
          bret = bgp_update_form(&update, msg_buf, sizeof(msg->hdr));
          EXPECT_EQ(false, bret);

          bret = bgp_update_form(&update, msg_buf, sizeof(msg_buf));
          EXPECT_EQ(true, bret);
          // Check header.
          EXPECT_EQ(BGP_MSG_UPDATE, msg->hdr.type);
          ptr = msg->msg.update;

          // Check withdrawn.
          length = ntohs(*(uint16_t *)ptr);
          EXPECT_EQ(update.withdrawn_length, length);
          ptr += sizeof(uint16_t);
          memval = memcmp(ptr, update.withdrawn, update.withdrawn_length);
          EXPECT_EQ(0, memval);
          ptr += update.withdrawn_length;

          // Check attributes.
          length = ntohs(*(uint16_t *)ptr);
          EXPECT_LT(0, length);
          ptr += sizeof(uint16_t);
          attr = root_atr;
          while (attr)
            {
              struct bgp_path_attr *attr_head = (struct bgp_path_attr *)ptr;
              union
                {
                  uint8_t *ptr;
                  struct bgp_as_path_network *path;
                  struct sukat_bgp_aggregator *aggregator;
                  uint32_t *val32;
                } payload;

              EXPECT_EQ(attr_head->type, attr->attr_type);
              ptr += sizeof(*attr_head);
              if (attr_head->flags.extended)
                {
                  ptr += 2;
                }
              else
                {
                  ptr += 1;
                }
              payload.ptr = ptr;
              memval =
                memcmp(&attr_head->flags, &attr->flags, sizeof(attr->flags));
              EXPECT_EQ(0, memval);
              switch (attr->attr_type)
                {
                case SUKAT_BGP_ATTR_ORIGIN:
                  EXPECT_EQ(*payload.ptr, attr->value.origin);
                  ptr++;
                  break;
                case SUKAT_BGP_ATTR_AS_PATH:
                  EXPECT_EQ(payload.path->type, attr->value.as_path.type);
                  EXPECT_EQ(payload.path->number_of_as_numbers,
                            attr->value.as_path.number_of_as_numbers);
                  ptr += sizeof(*payload.path);
                  for (i = 0; i < attr->value.as_path.number_of_as_numbers; i++)
                    {
                      val16 = ntohs(payload.path->as_numbers[i]);
                      EXPECT_EQ(attr->value.as_path.as_numbers[i], val16);
                      ptr += sizeof(uint16_t);
                    }
                  break;
                case SUKAT_BGP_ATTR_NEXT_HOP:
                case SUKAT_BGP_ATTR_MULTI_EXIT_DISC:
                case SUKAT_BGP_ATTR_LOCAL_PREF:
                  EXPECT_EQ(ntohl(*payload.val32), attr->value.next_hop);
                  ptr += sizeof(uint32_t);
                  break;
                case SUKAT_BGP_ATTR_AGGREGATOR:
                  val16 = ntohs(payload.aggregator->as_number);
                  EXPECT_EQ(attr->value.aggregator.as_number, val16);
                  val32 = ntohl(payload.aggregator->ip);
                  EXPECT_EQ(attr->value.aggregator.ip, val32);
                  ptr += sizeof(*payload.aggregator);
                  break;
                case SUKAT_BGP_ATTR_ATOMIC_AGGREGATE:
                  break;
                default:
                  EXPECT_EQ(true, false);
                  break;
                }
              attr = attr->next;
            }

          // Check reachability.
          length = ntohs(msg->hdr.length) - (ptr - msg_buf);
          EXPECT_EQ(update.reachability_length, length);
          memval = memcmp(update.reachability, ptr, length);
          EXPECT_EQ(0, memval);
        }

      send_ret = sukat_bgp_send_update(peer2, peer1_from_peer2, &update);
      EXPECT_EQ(SUKAT_SEND_OK, send_ret);

      tctx.update_should = true;
      err = sukat_bgp_read(peer1, 100);
      EXPECT_EQ(0, err);
      EXPECT_EQ(true, tctx.update_visited);
      tctx.update_should = tctx.update_visited = false;
    }

    {
      sukat_bgp_peer_t *explicit_peer;
      const struct sukat_sock_params_inet pinet =
        {
          .ip = "127.0.0.1",
          .port = nullptr
        };
      const bgp_id_t id =
        {
          .as_num = 555,
          .bgp_id = 12345,
          .version = 0
        };

      explicit_peer =
        sukat_bgp_peer_add(peer2, &default_params.pinet, &pinet, &id);
      EXPECT_NE(nullptr, explicit_peer);

      err = sukat_bgp_read(peer1, 100);
      EXPECT_EQ(0, err);

      tctx.open_visited = false;
      tctx.match_as_num = peer1_as;
      tctx.match_bgp_id = peer1_bgp;
      tctx.open_should_visit = true;

      err = sukat_bgp_read(peer2, 100);
      EXPECT_EQ(0, err);

      tctx.open_visited = false;
      tctx.match_as_num = id.as_num;
      tctx.match_bgp_id = id.bgp_id;
      tctx.open_should_visit = true;

      tctx.keepalive_should = true;
      tctx.keepalive_visited = false;
      err = sukat_bgp_read(peer1, 100);
      EXPECT_EQ(true, tctx.open_visited);
      EXPECT_EQ(true, tctx.keepalive_visited);
      tctx.keepalive_visited = tctx.keepalive_should = tctx.open_should_visit =
        tctx.open_visited = false;
      sukat_bgp_disconnect(peer2, explicit_peer);
    }

  sukat_bgp_disconnect(peer1, peer2_from_peer1);
  sukat_bgp_disconnect(peer2, peer1_from_peer2);
  sukat_bgp_destroy(peer2);
  sukat_bgp_destroy(peer1);
}

TEST(UtilTest, Ranges)
{
  struct sukat_util_range_values values = {};
  bool bret;
  char ipstr[INET6_ADDRSTRLEN];
  uint32_t value4;
  __int128 value16;

  bret = sukat_util_range_to_integers("1-5", SUKAT_UTIL_RANGE_INPUT_INTEGER,
                                      &values);
  EXPECT_EQ(true, bret);
  EXPECT_EQ(values.type, SUKAT_UTIL_RANGE_VALUE_4BYTE);
  EXPECT_EQ(values.start4, 1);
  EXPECT_EQ(values.end4, 5);
  EXPECT_EQ(values.count4, 4);

  memset(&values, 0, sizeof(values));
  bret = sukat_util_range_to_integers("1-429496729500",
                                      SUKAT_UTIL_RANGE_INPUT_INTEGER, &values);
  EXPECT_EQ(true, bret);
  EXPECT_EQ(values.type, SUKAT_UTIL_RANGE_VALUE_16BYTE);
  EXPECT_EQ(values.start16, 1);
  EXPECT_EQ(values.end16, 429496729500);
  EXPECT_EQ(values.count16, 429496729500 - 1);

  bret = sukat_util_range_to_integers("1.2.3.4-1.2.3.254",
                                      SUKAT_UTIL_RANGE_INPUT_IP, &values);
  EXPECT_EQ(true, bret);
  EXPECT_EQ(values.type, SUKAT_UTIL_RANGE_VALUE_4BYTE);
  snprintf(ipstr, sizeof(ipstr), "1.2.3.4");
  int ret = inet_pton(AF_INET, ipstr, &value4);
  EXPECT_EQ(1, ret);
  EXPECT_EQ(values.start4, ntohl(value4));
  snprintf(ipstr, sizeof(ipstr), "1.2.3.254");
  ret = inet_pton(AF_INET, ipstr, &value4);
  EXPECT_EQ(1, ret);
  EXPECT_EQ(values.end4, ntohl(value4));
  EXPECT_EQ(values.count4, 250);

  bret = sukat_util_range_to_integers("ff01::1-ff01::ffff",
                                      SUKAT_UTIL_RANGE_INPUT_IP, &values);
  EXPECT_EQ(true, bret);
  EXPECT_EQ(values.type, SUKAT_UTIL_RANGE_VALUE_16BYTE);
  snprintf(ipstr, sizeof(ipstr), "ff01::1");
  ret = inet_pton(AF_INET6, ipstr, &value16);
  EXPECT_EQ(1, ret);
  EXPECT_EQ(values.start16, sukat_util_ntohlll(value16));
  snprintf(ipstr, sizeof(ipstr), "ff01::ffff");
  ret = inet_pton(AF_INET6, ipstr, &value16);
  EXPECT_EQ(1, ret);
  EXPECT_EQ(values.end16, sukat_util_ntohlll(value16));
  EXPECT_EQ(values.count16, UINT16_MAX - 1);
}
