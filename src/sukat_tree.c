/*!
 * @file sukat_tree.h
 * @brief Tree structure for storing data.
 *
 * @addtogroup sukat_tree
 * @{
 */
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "sukat_tree.h"
#include "tree_binary.h"
#include "sukat_log_internal.h"

static int node_height(sukat_tree_node_t *node)
{
  if (!node)
    {
      return -1;
    }
  return node->meta.height;
}

static void height_count(sukat_tree_node_t *node)
{
  assert(node != NULL);
#define MAX(x, y) ((x > y) ? x : y)
  node->meta.height =
    MAX(node_height(node->left), node_height(node->right)) + 1;
#undef MAX
}

sukat_tree_ctx_t *sukat_tree_create(struct sukat_drawer_params *params,
                                    struct sukat_drawer_cbs *cbs)
{
  sukat_tree_ctx_t *ctx;

  if (!params)
    {
      return NULL;
    }
  ctx = (sukat_tree_ctx_t *)calloc(1, sizeof(*ctx));
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

static void height_update_up(sukat_tree_node_t *node,
                             __attribute((unused))bool rebalance)
{
  while (node)
    {
      height_count(node);
      node = node->parent;
    }
}

void sukat_tree_remove(sukat_tree_ctx_t *ctx, sukat_tree_node_t *node)
{
  sukat_tree_node_t *update_from = tree_binary_detach(ctx, node);

  if (update_from && !ctx->destroyed)
    {
      height_update_up(update_from, true);
    }
  tree_binary_node_free(ctx, node);
}

sukat_tree_node_t *sukat_tree_find(sukat_tree_ctx_t *ctx, void *key)
{
  return tree_binary_find(ctx, ctx->head, key);
}

sukat_tree_node_t *sukat_tree_add(sukat_tree_ctx_t *ctx, void *data)
{
  sukat_tree_node_t *node = tree_binary_insert(ctx, data);

  if (!node)
    {
      return NULL;
    }
  height_update_up(node, true);
  // TODO: balance.

  return node;
};

void sukat_tree_depth_first(sukat_tree_ctx_t *ctx, sukat_drawer_node_cb node_cb,
                            void *caller_ctx)
{
  tree_binary_depth_first(ctx, node_cb, caller_ctx);
}

/*! }@ */
