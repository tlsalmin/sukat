/*!
 * @file tree_avl.c
 * @brief Tree structure for storing data.
 *
 * @addtogroup tree_avl
 * @{
 */
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "tree_avl.h"
#include "tree_binary.h"
#include "sukat_log_internal.h"

static int node_height(tree_node_t *node)
{
  if (!node)
    {
      return -1;
    }
  return node->meta.height;
}

static void height_count(tree_node_t *node)
{
  assert(node != NULL);
#define MAX(x, y) ((x > y) ? x : y)
  node->meta.height =
    MAX(node_height(node->left), node_height(node->right)) + 1;
#undef MAX
}

static int node_balance_get(tree_node_t *node)
{
  assert(node != NULL);
  int height_left = (node->left) ? node->left->meta.height : -1,
      height_right = (node->right) ? node->right->meta.height : -1;

  return height_left - height_right;
}

tree_ctx_t *tree_avl_create(struct sukat_drawer_params *params,
                                  struct sukat_drawer_cbs *cbs)
{
  tree_ctx_t *ctx;

  if (!params)
    {
      return NULL;
    }
  ctx = (tree_ctx_t *)calloc(1, sizeof(*ctx));
  if (!ctx)
    {
      return NULL;
    }
  ctx->type = SUKAT_DRAWER_TREE_AVL;
  if (cbs)
    {
      memcpy(&ctx->cbs, cbs, sizeof(*cbs));
    }
  if (params)
    {
      memcpy(&ctx->params, params, sizeof(*params));
    }
  DBG(ctx, "Created tree %p", ctx);
  return ctx;
}

static bool avl_rebalance(tree_ctx_t *ctx, tree_node_t *node, int balance)
{
  if (balance > 1)
    {
      tree_node_t *left = node->left;

      if (node_balance_get(left) < 0)
        {
          tree_binary_rotate_left(ctx, left);
          height_count(left);
        }
      tree_binary_rotate_right(ctx, node);
      return true;
    }
  else if (balance < -1)
    {
      tree_node_t *right = node->right;

      if (node_balance_get(right) > 0)
          {
            tree_binary_rotate_right(ctx, right);
            height_count(right);
          }
      tree_binary_rotate_left(ctx, node);
      return true;
    }
  return false;
}

static void height_update_up(tree_ctx_t *ctx,
                             tree_node_t *node, bool rebalance)
{
  while (node)
    {
      height_count(node);
      if (rebalance)
        {
          int balance = node_balance_get(node);

          if (avl_rebalance(ctx, node, balance) == true)
            {
              height_count(node);
            }
        }
      node = node->parent;
    }
}

void tree_avl_remove(tree_ctx_t *ctx, tree_node_t *node)
{
  tree_node_t *update_from = tree_binary_detach(ctx, node);

  if (update_from && !ctx->destroyed)
    {
      height_update_up(ctx, update_from, true);
    }
  tree_binary_node_free(ctx, node);
}

tree_node_t *sukat_tree_find(tree_ctx_t *ctx, void *key)
{
  return tree_binary_find(ctx, ctx->root, key);
}

tree_node_t *tree_avl_add(tree_ctx_t *ctx, void *data)
{
  tree_node_t *node = tree_binary_insert(ctx, data);

  if (!node)
    {
      return NULL;
    }
  height_update_up(ctx, node, true);

  return node;
};

/*! }@ */
