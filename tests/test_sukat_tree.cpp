#include "gtest/gtest.h"
#include "test_common.h"

extern "C"{
#include "sukat_log_internal.c"
#include "sukat_tree.c"
}

static int tree_test_cmp_cb(void *n1, void *n2, bool find)
{
  if (!find)
    {
      int a = *(int *)n1, b = *(int *)n2;
      return a - b;
    }
  return 0;
}

// The fixture for testing class Project1. From google test primer.
class sukat_tree_test : public ::testing::Test
{
protected:
  // You can remove any or all of the following functions if its body is empty.

  sukat_tree_test() {
      memset(&default_params, 0, sizeof(default_params));
      memset(&default_cbs, 0, sizeof(default_cbs));
      default_cbs.log_cb = test_log_cb;
      default_cbs.cmp_cb = tree_test_cmp_cb;
      // You can do set-up work for each test here.
  }

  virtual ~sukat_tree_test() {
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

  struct sukat_tree_params default_params;
  struct sukat_tree_cbs default_cbs;
  // Objects declared here can be used by all tests
};

TEST_F(sukat_tree_test, sukat_tree_test_init)
{
  sukat_tree_ctx_t *ctx;
  struct sukat_tree_params params = { };

  ctx = sukat_tree_create(NULL, NULL);
  EXPECT_EQ(nullptr, ctx);

  ctx = sukat_tree_create(&params, NULL);
  EXPECT_NE(nullptr, ctx);

  sukat_tree_destroy(ctx);
}

TEST_F(sukat_tree_test, sukat_tree_test_rotates)
{
  sukat_tree_ctx_t *ctx;
  sukat_tree_node_t *node;
  int testvalues[] = {-1, 4, 5, 6, -3, 3};
  size_t i = 0;

  ctx = sukat_tree_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, ctx);

  for (i = 0; i < sizeof(testvalues) / sizeof(*testvalues); i++)
    {
      node = binary_insert(ctx, &testvalues[i]);
      EXPECT_NE(nullptr, ctx);
      EXPECT_EQ(testvalues[i], *(int *)node->data);
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

  rotate_left(ctx, ctx->head);

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

  rotate_left(ctx, ctx->head->right);

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

  rotate_right(ctx, ctx->head);
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

  rotate_right(ctx, ctx->head);
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
