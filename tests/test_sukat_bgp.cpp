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
#include <stdlib.h>
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
      uint8_t open_should_visit:1;
      uint8_t open_visited:1;
      uint8_t disconnect_should:1;
      uint8_t keepalive_should:1;
      uint8_t keepalive_visited:1;
      uint8_t notification_should:1;
      uint8_t notification_visited:1;
      uint8_t unused:1;
  };
  sukat_bgp_peer_t *newest_client;
  uint8_t match_version;
  uint16_t match_as_num;
  uint32_t match_bgp_id;
  uint8_t match_error;
  uint8_t match_error_sub;
  size_t data_len;
  uint8_t *data;
};

void *open_cb(void *ctx, sukat_bgp_peer_t *peer, bgp_id_t *id,
              sukat_sock_event_t event)
{
  struct bgp_test_ctx *tctx = (struct bgp_test_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  EXPECT_NE(nullptr, peer);
  if (tctx)
    {
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

void keepalive_cb(void *ctx, __attribute__((unused)) sukat_bgp_peer_t *peer,
                  bgp_id_t *id)
{
  struct bgp_test_ctx *tctx = (struct bgp_test_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  EXPECT_NE(nullptr, peer);
  if (tctx)
    {
      EXPECT_EQ(true, tctx->keepalive_should);
      tctx->keepalive_visited = true;
      EXPECT_EQ(tctx->match_version, id->version);
      EXPECT_EQ(tctx->match_as_num, id->as_num);
      EXPECT_EQ(tctx->match_bgp_id, id->bgp_id);
    }
}

void notification_cb(void *ctx, __attribute__((unused)) sukat_bgp_peer_t *peer,
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
  peer1_from_peer2 = sukat_bgp_peer_add(peer2, &default_params.pinet);
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
  err = sukat_bgp_read(peer1, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.notification_visited);
  tctx.notification_should = tctx.notification_visited = false;

  sukat_bgp_disconnect(peer1, peer2_from_peer1);
  sukat_bgp_disconnect(peer2, peer1_from_peer2);
  sukat_bgp_destroy(peer2);
  sukat_bgp_destroy(peer1);
}

