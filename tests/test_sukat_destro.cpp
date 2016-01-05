#include <iostream>
#include <fstream>

#include "gtest/gtest.h"
#include "test_common.h"

extern "C"{
#include "sukat_log_internal.c"
#include "delayed_destruction.c"
}

class destro_test : public ::testing::Test
{
protected:
  destro_test() {
  }

  virtual ~destro_test() {
  }

  virtual void SetUp() {
      memset(&default_params, 0, sizeof(default_params));
      memset(&default_cbs, 0, sizeof(default_cbs));
      default_cbs.log_cb = test_log_cb;
  }

  virtual void TearDown() {
  }

  struct destro_params default_params;
  struct destro_cbs default_cbs;
};

struct destro_test_flags
{
  uint8_t close_should:1;
  uint8_t close_visited:1;
  uint8_t free_should:1;
  uint8_t free_visited:1;
  uint8_t unused:4;
};

struct destro_test_main
{
  struct destro_test_flags flags;
};

struct destro_test_client_ctx
{
  destro_client_t destro_ctx;
  struct destro_test_flags flags;
};

static void destro_test_close(void *main_ctx, void *client_ctx)
{
  struct destro_test_main *tctx = (struct destro_test_main *)main_ctx;
  struct destro_test_client_ctx *tclient =
    (struct destro_test_client_ctx *)client_ctx;
  struct destro_test_flags *flags = (tclient) ? &tclient->flags : &tctx->flags;

  EXPECT_EQ(true, flags->close_should);
  flags->close_visited = true;
}

static void destro_test_free(void *main_ctx, void *client_ctx)
{
  struct destro_test_main *tctx = (struct destro_test_main *)main_ctx;
  struct destro_test_client_ctx *tclient =
    (struct destro_test_client_ctx *)client_ctx;
  struct destro_test_flags *flags = (tclient) ? &tclient->flags : &tctx->flags;

  EXPECT_EQ(true, flags->free_should);
  flags->free_visited = true;
}

TEST_F(destro_test, destro_test_delayed)
{
  struct destro_test_main tctx = { };
  const size_t n_clients = 20;
  struct destro_test_client_ctx clients[n_clients] = { };
  size_t i, d1 = 3;
  destro_t *ctx;

  ctx = destro_create(NULL, NULL);
  EXPECT_EQ(nullptr, ctx);

  default_params.main_ctx = (void *)&tctx;
  default_cbs.close = destro_test_close;
  default_cbs.dfree = destro_test_free;

  ctx = destro_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);

  // Delete one and see that free isn't called but close is.
  destro_cb_enter(ctx);
  clients[d1].flags.close_should = true;
  destro_delete(ctx, &clients[d1].destro_ctx);
  EXPECT_EQ(true, clients[d1].flags.close_visited);
  EXPECT_EQ(false, clients[d1].flags.free_visited);

  clients[d1].flags.close_should = false;
  clients[d1].flags.free_should = true;
  destro_cb_exit(ctx);
  EXPECT_EQ(true, clients[d1].flags.free_visited);

  // Same for all
  destro_cb_enter(ctx);
  for (i = 0; i < n_clients; i++)
    {
      if (i == d1)
        {
          continue;
        }
      clients[i].flags.close_should = true;
      destro_delete(ctx, &clients[i].destro_ctx);
      EXPECT_EQ(true, clients[i].flags.close_visited);
      clients[i].flags.close_should = clients[i].flags.close_visited = false;
    }
  destro_delete(ctx, NULL);

  for (i = 0; i < n_clients; i++)
    {
      clients[i].flags.free_should = true;
    }
  tctx.flags.close_should = tctx.flags.free_should = true;
  destro_cb_exit(ctx);
  for (i = 0; i < n_clients; i++)
    {
      if (i == d1)
        {
          continue;
        }
      EXPECT_EQ(true, clients[i].flags.free_visited);
    }
  EXPECT_EQ(true, tctx.flags.free_visited);
  EXPECT_EQ(true, tctx.flags.close_visited);
}

TEST_F(destro_test, destro_test_straight)
{
  struct destro_test_main tctx = { };
  const size_t n_clients = 20;
  struct destro_test_client_ctx clients[n_clients] = { };
  size_t i;
  destro_t *ctx;

  default_params.main_ctx = (void *)&tctx;
  default_cbs.close = destro_test_close;
  default_cbs.dfree = destro_test_free;

  ctx = destro_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);

  for (i = 0; i < n_clients; i++)
    {
      clients[i].flags.close_should = clients[i].flags.free_should = true;
      destro_delete(ctx, &clients[i].destro_ctx);
      EXPECT_EQ(true, clients[i].flags.close_visited);
      EXPECT_EQ(true, clients[i].flags.free_visited);
      EXPECT_EQ(false, destro_is_deleted(ctx, NULL));
      EXPECT_EQ(true, destro_is_deleted(ctx, &clients[i].destro_ctx));
    }
  tctx.flags.free_should = tctx.flags.close_should = true;
  destro_delete(ctx, NULL);
  EXPECT_EQ(true, tctx.flags.close_visited);
  EXPECT_EQ(true, tctx.flags.free_visited);
}

/*!
 * Just bumping coverage to 100%. Check with valgrind / sanitize build for leak
 */
TEST_F(destro_test, destro_test_no_cbs)
{
  void *main_ctx = malloc(8);
  void *client1 = calloc(1, sizeof(destro_client_t)),
       *client2 = calloc(1, sizeof(destro_client_t));
  destro_t *ctx;

  default_params.main_ctx = main_ctx;
  ctx = destro_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, ctx);

  // Not delayed.
  destro_delete(ctx, (destro_client_t *)client1);

  // Delayed.
  destro_cb_enter(ctx);
  destro_delete(ctx, (destro_client_t *)client2);
  destro_delete(ctx, NULL);
  EXPECT_EQ(true, destro_is_deleted(ctx, NULL));
  EXPECT_EQ(true, destro_is_deleted(ctx, (destro_client_t *)client2));
  destro_cb_exit(ctx);
}
