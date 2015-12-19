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

static void height_update_up(tree_node_t *node,
                             __attribute((unused))bool rebalance)
{
  while (node)
    {
      height_count(node);
      node = node->parent;
    }
}

void tree_avl_remove(tree_ctx_t *ctx, tree_node_t *node)
{
  tree_node_t *update_from = tree_binary_detach(ctx, node);

  if (update_from && !ctx->destroyed)
    {
      height_update_up(update_from, true);
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
  height_update_up(node, true);
  // TODO: balance.

  return node;
};

/*! }@ */
