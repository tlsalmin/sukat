#include <iostream>
#include <random>

#include "gtest/gtest.h"
#include "test_common.h"

extern "C"{
#include "sukat_log_internal.c"
#include "sukat_sock.c"
#include "sukat_event.h"
#include <stdlib.h>
}

class sukat_sock_test : public ::testing::Test
{
protected:
  // You can remove any or all of the following functions if its body is empty.

  sukat_sock_test() {
      // You can do set-up work for each test here.
      memset(&default_cbs, 0, sizeof(default_cbs));
      default_cbs.log_cb = test_log_cb;
      memset(&default_params, 0, sizeof(default_params));

  }

  virtual ~sukat_sock_test() {
      // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up and
  // cleaning up each test, you can define the following methods:
  virtual void SetUp() {
      // Code here will be called immediately after the constructor (right
      // before each test).
  }

  virtual void TearDown() {
      // Code here will be called immediately after each test (right
      // before the destructor).
  }
  void get_random_port(struct sukat_sock_params *params)
    {
      static bool random_seeded;

      if (!random_seeded)
        {
          FILE *urandom = fopen("/dev/urandom", "r");
          unsigned int seed;
          size_t n_read;

          EXPECT_NE(nullptr, urandom);
          n_read = fread(&seed, sizeof(seed), 1, urandom);
          EXPECT_EQ(1, n_read);
          fclose(urandom);

          srand(seed);

          random_seeded = true;
        }

      params->ptipc.port_type = 63 + ((uint32_t)rand() % UINT32_MAX);
      params->ptipc.port_instance = ((uint32_t)rand() % UINT32_MAX);
    }

  bool wait_for_tipc_server(sukat_sock_ctx_t *ctx, uint32_t name_type,
                            uint32_t name_instance, int wait)
    {
      struct sockaddr_tipc topsrv;
      struct tipc_subscr subscr;
      struct tipc_event event;

      int sd = socket(AF_TIPC, SOCK_SEQPACKET, 0);

      memset(&topsrv, 0, sizeof(topsrv));
      topsrv.family = AF_TIPC;
      topsrv.addrtype = TIPC_ADDR_NAME;
      topsrv.addr.name.name.type = TIPC_TOP_SRV;
      topsrv.addr.name.name.instance = TIPC_TOP_SRV;

      /* Connect to topology server */

      if (0 > connect(sd, (struct sockaddr *)&topsrv, sizeof(topsrv))) {
          ERR(ctx, "Client: failed to connect to topology server: %S",
              strerror(errno));
          return false;
      }

      subscr.seq.type = htonl(name_type);
      subscr.seq.lower = htonl(name_instance);
      subscr.seq.upper = htonl(name_instance);
      subscr.timeout = htonl(wait);
      subscr.filter = htonl(TIPC_SUB_SERVICE);

      if (send(sd, &subscr, sizeof(subscr), 0) != sizeof(subscr)) {
          ERR(ctx, "Client: failed to send subscription: %s",strerror(errno));
          return false;
      }
      /* Now wait for the subscription to fire */

      if (recv(sd, &event, sizeof(event), 0) != sizeof(event)) {
          ERR(ctx, "Client: failed to receive event: %s", strerror(errno));
          return false;
      }
      if (event.event != htonl(TIPC_PUBLISHED)) {
          ERR(ctx, "Client: server {%u,%u} not published within %u [s]\n: %s",
                 name_type, name_instance, wait/1000, strerror(errno));
          return false;
      }
      LOG(ctx, "Server published TIPC!");

      close(sd);
      return true;
    }

  // Objects declared here can be used by all tests
  struct sukat_sock_cbs default_cbs;
  struct sukat_sock_params default_params;
};

struct test_ctx
{
  int yeah;
};

TEST_F(sukat_sock_test, sukat_sock_test_tipc)
{
  sukat_sock_ctx_t *ctx, *client_ctx;
  struct test_ctx tctx = { };
  bool bret;
  int err;

  default_params.caller_ctx = &tctx;
  default_params.server = true;
  default_params.domain = AF_TIPC;
  default_params.type = SOCK_SEQPACKET;

  get_random_port(&default_params);

  ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);

  default_params.server = false;
  bret = wait_for_tipc_server(ctx, default_params.ptipc.port_type,
                              default_params.ptipc.port_instance, 1000);
  EXPECT_EQ(true, bret);

  client_ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client_ctx);

  err = sukat_sock_read(ctx, sukat_sock_get_epoll_fd(ctx), 0, 0);
  EXPECT_NE(-1, err);

  sukat_sock_destroy(ctx);
  sukat_sock_destroy(client_ctx);
}
