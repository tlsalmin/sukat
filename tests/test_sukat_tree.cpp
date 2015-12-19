#include "gtest/gtest.h"
#include "test_common.h"

extern "C"{
#include "sukat_log_internal.c"
#include "tree_binary.c"
#include "sukat_tree.c"
}

static int tree_test_cmp_cb(void *n1, void *n2,
                            __attribute__((unused))bool find)
{
  int a = *(int *)n1, b = *(int *)n2;
  return a - b;
}

class sukat_tree_test : public ::testing::Test
{
protected:
  sukat_tree_test() {
  }

  virtual ~sukat_tree_test() {
  }

  virtual void SetUp() {
      sukat_tree_node_t *node;
      size_t i = 0;

      memset(&default_params, 0, sizeof(default_params));
      memset(&default_cbs, 0, sizeof(default_cbs));
      default_cbs.log_cb = test_log_cb;
      default_cbs.cmp_cb = tree_test_cmp_cb;
      ctx = sukat_tree_create(&default_params, &default_cbs);
      EXPECT_NE(nullptr, ctx);

      for (i = 0; i < testvalues_len; i++)
        {
          node = tree_binary_insert(ctx, &testvalues[i]);
          EXPECT_NE(nullptr, ctx);
          EXPECT_EQ(testvalues[i], *(int *)node->data);
          height_update_up(node, false);
        }
      /* Should be
       *            -1
       *            / \
       *          -3   4
       *              / \
       *             3   5
       *                  \
       *                   6
       */
  }

  virtual void TearDown() {
      tree_binary_destroy(ctx);
  }

  struct sukat_drawer_params default_params;
  struct sukat_drawer_cbs default_cbs;
  sukat_tree_ctx_t *ctx;
  int testvalues[6] = {-1, 4, 5, 6, -3, 3};
  size_t testvalues_len = sizeof(testvalues) / sizeof(*testvalues);
};

TEST_F(sukat_tree_test, sukat_tree_test_init)
{
  sukat_tree_ctx_t *ctx_other;
  struct sukat_drawer_params params = { };

  ctx_other = sukat_tree_create(NULL, NULL);
  EXPECT_EQ(nullptr, ctx_other);

  ctx_other = sukat_tree_create(&params, NULL);
  EXPECT_NE(nullptr, ctx_other);

  tree_binary_destroy(ctx_other);
}

TEST_F(sukat_tree_test, sukat_tree_test_rotates)
{
  sukat_tree_node_t *node;

  EXPECT_EQ(*(int *)ctx->head->data, testvalues[0]);
  EXPECT_EQ(*(int *)ctx->head->left->data, testvalues[4]);
  EXPECT_EQ(*(int *)ctx->head->right->data, testvalues[1]);
  EXPECT_EQ(*(int *)ctx->head->right->left->data, testvalues[5]);
  EXPECT_EQ(*(int *)ctx->head->right->right->data, testvalues[2]);
  EXPECT_EQ(*(int *)ctx->head->right->right->right->data, testvalues[3]);

  // Check heights.
  EXPECT_EQ(3, ctx->head->meta.height);
  EXPECT_EQ(0, ctx->head->left->meta.height);
  EXPECT_EQ(2, ctx->head->right->meta.height);
  EXPECT_EQ(0, ctx->head->right->left->meta.height);
  EXPECT_EQ(1, ctx->head->right->right->meta.height);
  EXPECT_EQ(0, ctx->head->right->right->right->meta.height);

  node = ctx->head;
  tree_binary_rotate_left(ctx, node);
  height_update_up(node, false);

  /* Should be
   *             4
   *            / \
   *          -1   5
   *          / \   \
   *        -3   3   6
   */
  EXPECT_EQ(testvalues[1], *(int *)ctx->head->data);
  EXPECT_EQ(testvalues[0], *(int *)ctx->head->left->data);
  EXPECT_EQ(testvalues[4], *(int *)ctx->head->left->left->data);
  EXPECT_EQ(testvalues[5], *(int *)ctx->head->left->right->data);
  EXPECT_EQ(testvalues[2], *(int *)ctx->head->right->data);
  EXPECT_EQ(testvalues[3], *(int *)ctx->head->right->right->data);

  // Check heights.
  EXPECT_EQ(2, ctx->head->meta.height);
  EXPECT_EQ(1, ctx->head->left->meta.height);
  EXPECT_EQ(0, ctx->head->left->left->meta.height);
  EXPECT_EQ(0, ctx->head->left->right->meta.height);
  EXPECT_EQ(1, ctx->head->right->meta.height);
  EXPECT_EQ(0, ctx->head->right->right->meta.height);

  node = ctx->head->right;
  tree_binary_rotate_left(ctx, node);
  height_update_up(node, false);

  /* Should be
   *             4
   *            / \
   *          -1   6
   *          / \  |
   *        -3   3 5
   */

  EXPECT_EQ(testvalues[3], *(int *)ctx->head->right->data);
  EXPECT_EQ(testvalues[2], *(int *)ctx->head->right->left->data);

  // Check heights.
  EXPECT_EQ(2, ctx->head->meta.height);
  EXPECT_EQ(1, ctx->head->right->meta.height);
  EXPECT_EQ(0, ctx->head->right->left->meta.height);

  node = ctx->head;
  tree_binary_rotate_right(ctx, node);
  height_update_up(node, false);
  /* Should be
   *            -1
   *            / \
   *          -3   4
   *              / \
   *             3   6
   *                /
   *               5
   */
  EXPECT_EQ(testvalues[0], *(int *)ctx->head->data);
  EXPECT_EQ(testvalues[4], *(int *)ctx->head->left->data);
  EXPECT_EQ(testvalues[1], *(int *)ctx->head->right->data);
  EXPECT_EQ(testvalues[5], *(int *)ctx->head->right->left->data);
  EXPECT_EQ(testvalues[3], *(int *)ctx->head->right->right->data);
  EXPECT_EQ(testvalues[2], *(int *)ctx->head->right->right->left->data);

  // Check heights.
  EXPECT_EQ(3, ctx->head->meta.height);
  EXPECT_EQ(0, ctx->head->left->meta.height);
  EXPECT_EQ(2, ctx->head->right->meta.height);
  EXPECT_EQ(0, ctx->head->right->left->meta.height);
  EXPECT_EQ(1, ctx->head->right->right->meta.height);
  EXPECT_EQ(0, ctx->head->right->right->left->meta.height);

  node = ctx->head;
  tree_binary_rotate_right(ctx, node);
  height_update_up(node, false);
  /* Should be
   *            -3
   *              \
   *              -1
   *                \
   *                 4
   *                / \
   *               3   6
   *                  /
   *                 5
   */
  EXPECT_EQ(testvalues[4], *(int *)ctx->head->data);
  EXPECT_EQ(testvalues[0], *(int *)ctx->head->right->data);
  EXPECT_EQ(testvalues[1], *(int *)ctx->head->right->right->data);
  EXPECT_EQ(testvalues[5], *(int *)ctx->head->right->right->left->data);
  EXPECT_EQ(testvalues[3], *(int *)ctx->head->right->right->right->data);
  EXPECT_EQ(testvalues[2], *(int *)ctx->head->right->right->right->left->data);

  // Check heights
  EXPECT_EQ(4, ctx->head->meta.height);
  EXPECT_EQ(3, ctx->head->right->meta.height);
  EXPECT_EQ(2, ctx->head->right->right->meta.height);
  EXPECT_EQ(0, ctx->head->right->right->left->meta.height);
  EXPECT_EQ(1, ctx->head->right->right->right->meta.height);
  EXPECT_EQ(0, ctx->head->right->right->right->left->meta.height);
}

static void validate_find(sukat_tree_node_t *node, int key)
{
  EXPECT_NE(nullptr, node);
  ASSERT_NE(nullptr, binary_tree_node_data(node));
  EXPECT_EQ(key, *(int *)binary_tree_node_data(node));
}

TEST_F(sukat_tree_test, sukat_tree_test_find)
{
  sukat_tree_node_t *node;
  size_t i;
  int key = 424124214;

  /* Find all. */
  for (i = 0; i < testvalues_len; i++)
    {
      node = sukat_tree_find(ctx, (void *)&testvalues[i]);
      validate_find(node, testvalues[i]);
    }

  /* Find something not there */
  node = sukat_tree_find(ctx, (void *)&key);
  EXPECT_EQ(nullptr, node);
}

struct test_df_data
{
  size_t values_iter;
  size_t values_size;
  int *values;
  size_t *heights;
};

static bool test_df_check_cb(sukat_drawer_node_t *dnode, void *caller_data)
{
  struct test_df_data *tctx = (struct test_df_data *)caller_data;
  sukat_tree_node_t *node = (sukat_tree_node_t *)dnode;

  EXPECT_LT(tctx->values_iter, tctx->values_size);
  EXPECT_EQ(tctx->values[tctx->values_iter],
            *(int *)binary_tree_node_data(node));
  if (tctx->heights)
    {
      EXPECT_EQ(tctx->heights[tctx->values_iter], node->meta.height);
    }
  tctx->values_iter++;
  return true;
}

TEST_F(sukat_tree_test, sukat_tree_test_remove)
{
  sukat_tree_node_t *node, *update;
  size_t key_single = 5, key_one_child = 1, key_two_child = 2, root_key = 0;
  size_t i;
  struct test_df_data tctx = { };

  /* Remove without children */
  node = sukat_tree_find(ctx, (void *)&testvalues[key_single]);
  ASSERT_NE(nullptr, node);

  update = tree_binary_detach(ctx, node);
  free(node);
  node = sukat_tree_find(ctx, (void *)&testvalues[key_single]);
  ASSERT_EQ(nullptr, node);

  height_update_up(update, false);

  /* Check that everything else is still in place. */
  for (i = 0; i < testvalues_len; i++)
    {
      if (i == key_single)
        {
          continue;
        }
      node = sukat_tree_find(ctx, (void *)&testvalues[i]);
      validate_find(node, testvalues[i]);
    }

  /* Remove with one child */
  node = sukat_tree_find(ctx, (void *)&testvalues[key_one_child]);
  ASSERT_NE(nullptr, node);

  update = tree_binary_detach(ctx, node);
  free(node);
  node = sukat_tree_find(ctx, (void *)&testvalues[key_one_child]);
  ASSERT_EQ(nullptr, node);
  height_update_up(update, false);

  for (i = 0; i < testvalues_len; i++)
    {
      if (i == key_single || i == key_one_child)
        {
          continue;
        }
      node = sukat_tree_find(ctx, (void *)&testvalues[i]);
      validate_find(node, testvalues[i]);
    }

  node = tree_binary_insert(ctx, &testvalues[key_single]);
  EXPECT_NE(nullptr, node);
  height_update_up(node, false);
  node = tree_binary_insert(ctx, &testvalues[key_one_child]);
  EXPECT_NE(nullptr, node);
  height_update_up(node, false);

  /* Should be
   *            -1
   *            / \
   *          -3   5
   *              / \
   *             3   6
   *              \
   *               4
   */

  i = 0;
  tctx.values_size = 6;
  tctx.values = (int *)calloc(tctx.values_size, sizeof(*tctx.values));
  tctx.heights = (size_t *)calloc(tctx.values_size, sizeof(*tctx.heights));
  tctx.values[i] = -3;
  tctx.heights[i++] = 0;
  tctx.values[i] = 4;
  tctx.heights[i++] = 0;
  tctx.values[i] = 3;
  tctx.heights[i++] = 1;
  tctx.values[i] = 6;
  tctx.heights[i++] = 0;
  tctx.values[i] = 5;
  tctx.heights[i++] = 2;
  tctx.values[i] = -1;
  tctx.heights[i] = 3;

  tree_binary_depth_first(ctx, test_df_check_cb, &tctx);
  EXPECT_EQ(tctx.values_size, tctx.values_iter);
  free(tctx.values);
  free(tctx.heights);
  memset(&tctx, 0, sizeof(tctx));

  node = sukat_tree_find(ctx, (void *)&testvalues[key_two_child]);
  EXPECT_NE(nullptr, node);
  update = tree_binary_detach(ctx, node);
  tree_binary_node_free(ctx, node);
  node = sukat_tree_find(ctx, (void *)&testvalues[key_two_child]);
  EXPECT_EQ(nullptr, node);
  height_update_up(update, false);

  for (i = 0; i < testvalues_len; i++)
    {
      if (i == key_two_child)
        {
          continue;
        }
      node = sukat_tree_find(ctx, (void *)&testvalues[i]);
      validate_find(node, testvalues[i]);
    }
  /* Should be
   *            -1
   *            / \
   *          -3   6
   *              /
   *             3
   *              \
   *               4
   */

  i = 0;
  tctx.values_size = 5;
  tctx.values = (int *)calloc(tctx.values_size, sizeof(*tctx.values));
  tctx.heights = (size_t *)calloc(tctx.values_size, sizeof(*tctx.heights));
  tctx.values[i] = -3;
  tctx.heights[i++] = 0;
  tctx.values[i] = 4;
  tctx.heights[i++] = 0;
  tctx.values[i] = 3;
  tctx.heights[i++] = 1;
  tctx.values[i] = 6;
  tctx.heights[i++] = 2;
  tctx.values[i] = -1;
  tctx.heights[i] = 3;

  sukat_tree_depth_first(ctx, test_df_check_cb, &tctx);
  EXPECT_EQ(tctx.values_size, tctx.values_iter);
  free(tctx.values);
  free(tctx.heights);
  memset(&tctx, 0, sizeof(tctx));

  /* Remove root. */
  node = sukat_tree_find(ctx, (void *)&testvalues[root_key]);
  EXPECT_NE(nullptr, node);
  update = tree_binary_detach(ctx, node);
  tree_binary_node_free(ctx, node);
  height_update_up(update, false);
  node = sukat_tree_find(ctx, (void *)&testvalues[root_key]);
  EXPECT_EQ(nullptr, node);

  /* Should be
   *             3
   *            / \
   *          -3   6
   *              /
   *             4
   *
   *
   */

  i = 0;
  tctx.values_size = 4;
  tctx.values = (int *)calloc(tctx.values_size, sizeof(*tctx.values));
  tctx.heights = (size_t *)calloc(tctx.values_size, sizeof(*tctx.heights));
  tctx.values[i] = -3;
  tctx.heights[i++] = 0;
  tctx.values[i] = 4;
  tctx.heights[i++] = 0;
  tctx.values[i] = 6;
  tctx.heights[i++] = 1;
  tctx.values[i] = 3;
  tctx.heights[i] = 2;

  sukat_tree_depth_first(ctx, test_df_check_cb, &tctx);
  EXPECT_EQ(tctx.values_size, tctx.values_iter);
  free(tctx.values);
  free(tctx.heights);
  memset(&tctx, 0, sizeof(tctx));
}

