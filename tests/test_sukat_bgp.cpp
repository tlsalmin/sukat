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
      default_params.port = random_port;
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
      uint8_t unused:8;
  };
  sukat_bgp_client_t *newest_client;
  uint8_t match_version;
  uint16_t match_as_num;
  uint32_t match_bgp_id;
};

void *open_cb(void *ctx, sukat_bgp_client_t *client, uint8_t version,
              uint16_t as_num, uint32_t bgp_id)
{
  struct bgp_test_ctx *tctx = (struct bgp_test_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  if (tctx)
    {
      EXPECT_EQ(true, tctx->open_should_visit);
      tctx->open_visited = true;
      tctx->newest_client = client;
      EXPECT_EQ(tctx->match_version, version);
      EXPECT_EQ(tctx->match_as_num, as_num);
      EXPECT_EQ(tctx->match_bgp_id, bgp_id);
    }

  return NULL;
}

#if 0
TEST_F(sukat_bgp_test, sukat_bgp_test_init)
{
  sukat_bgp_t *server, *client;
  struct bgp_test_ctx tctx = { };
  const uint16_t server_as = 14, client_as = 15;
  const uint32_t server_bgp = 35, client_bgp = 36;
  char portbuf[strlen("65535") + 1];
  sukat_bgp_client_t *client_from_server, *server_from_client;
  uint16_t port;
  int err;

  // Shouldn't work with NULL parameters
  server = sukat_bgp_create(NULL, NULL);
  EXPECT_EQ(nullptr, server);

  default_params.my_as = server_as;
  default_params.bgp_id = server_bgp;
  default_params.caller_ctx = (void *)&tctx;
  default_params.server = true;
  default_cbs.open_cb = open_cb;

  server = sukat_bgp_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, server);

  default_params.server = false;
  default_params.my_as = client_as;
  default_params.bgp_id = client_bgp;

  port = sukat_sock_get_port(server->sock_ctx, NULL);
  EXPECT_LT(0, port);
  snprintf(portbuf, sizeof(portbuf), "%hu", port);
  default_params.port = portbuf;

  client = sukat_bgp_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, client);

  // Received on the server side
  tctx.match_as_num = server_as;
  tctx.match_bgp_id = server_bgp;
  tctx.match_version = 4;
  tctx.open_should_visit = true;

  err = sukat_bgp_read(server, 100);
  EXPECT_EQ(0, err);

  err = sukat_bgp_read(client, 100);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.open_visited);
  server_from_client = tctx.newest_client;
  tctx.open_visited = false;

  tctx.match_as_num = client_as;
  tctx.match_bgp_id = client_bgp;
  err = sukat_bgp_read(server, 100);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.open_visited);
  tctx.open_visited = false;
  client_from_server = tctx.newest_client;
  EXPECT_NE(nullptr, client_from_server);

  sukat_bgp_disconnect(server, client_from_server);
  sukat_bgp_disconnect(client, server_from_client);
  sukat_bgp_destroy(client);
  sukat_bgp_destroy(server);
}
#endif
