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
#include "sukat_log_internal.h"

struct sukat_tree_ctx
{
  sukat_tree_node_t *head;
  struct sukat_tree_params params;
  struct sukat_tree_cbs cbs;
  bool destroyed;
};

struct sukat_tree_node_ctx
{
  sukat_tree_node_t *parent;
  sukat_tree_node_t *left;
  sukat_tree_node_t *right;
  bool removed;
  union
    {
      int height;
    } meta;
  void *data;
};
static sukat_tree_node_t **parent_ptr_get(sukat_tree_ctx_t *tree,
                                          sukat_tree_node_t *node)
{
  if (!node->parent)
    {
      return &tree->head;
    }
  return (node->parent->left == node) ?
    &node->parent->left : &node->parent->right;
}

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

static void height_update_up(sukat_tree_node_t *node,
                             __attribute((unused))bool rebalance)
{
  while (node)
    {
      height_count(node);
      node = node->parent;
    }
}

static void rotate_left(sukat_tree_ctx_t *tree, sukat_tree_node_t *node,
                        bool update_up, bool rebalance)
{
  sukat_tree_node_t **parents_ptr, *right;
  assert(tree != NULL && node != NULL && node->right != NULL);

  parents_ptr = parent_ptr_get(tree, node);
  right = node->right;

  *parents_ptr = right;
  right->parent = node->parent;
  node->parent = right;
  node->right = right->left;
  if (right->left)
    {
      right->left->parent = node;
    }
  right->left = node;

  if (update_up)
    {
      /* Update heights. */
      height_update_up(node, rebalance);
    }
}

static void rotate_right(sukat_tree_ctx_t *tree, sukat_tree_node_t *node,
                         bool update_up, bool rebalance)
{
  sukat_tree_node_t **parents_ptr, *left;
  assert(tree != NULL && node != NULL && node->left != NULL);

  parents_ptr = parent_ptr_get(tree, node);
  left = node->left;

  *parents_ptr = left;
  left->parent = node->parent;
  node->parent = left;
  node->left = left->right;
  if (left->right)
    {
      left->right->parent = node;
    }
  left->right = node;

  if (update_up)
    {
      /* Update heights. */
      height_update_up(node, rebalance);
    }
}

sukat_tree_ctx_t *sukat_tree_create(struct sukat_tree_params *params,
                                    struct sukat_tree_cbs *cbs)
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

static sukat_tree_node_t *binary_insert(sukat_tree_ctx_t *ctx, void *data)
{
  sukat_tree_node_t **parents_ptr = NULL;
  sukat_tree_node_t *parent = NULL;

  if (!ctx || !ctx->cbs.cmp_cb)
    {
      ERR(ctx, "Missing %s.", (ctx) ? "compare function" : "context");
      return NULL;
    }
  if (!ctx->head)
    {
      parents_ptr = &ctx->head;
    }
  else
    {
      parents_ptr = &ctx->head;
      while (*parents_ptr != NULL)
        {
          int cmp_value = ctx->cbs.cmp_cb(data, (*parents_ptr)->data, false);

          if (cmp_value == 0)
            {
              ERR(ctx, "Data with key already exist");
              return NULL;
            }

          parent = *parents_ptr;
          parents_ptr = (cmp_value < 0) ? &((*parents_ptr)->left) :
            &((*parents_ptr)->right);
        }
      assert(parent != NULL);
    }
  assert(*parents_ptr == NULL);
  *parents_ptr = (sukat_tree_node_t*)calloc(1, sizeof(*ctx->head));
  (*parents_ptr)->data = data;
  (*parents_ptr)->parent = parent;

  return *parents_ptr;
}

void *sukat_tree_node_data(sukat_tree_node_t *node)
{
  if (node)
    {
      return node->data;
    }
  return NULL;
}

static void node_free(sukat_tree_ctx_t *ctx, sukat_tree_node_t *node)
{
  if (ctx->cbs.destroy_cb && !node->removed)
    {
      ctx->cbs.destroy_cb(sukat_tree_node_data(node));
    }
  free(node);
}

static sukat_tree_node_t *binary_minimum(sukat_tree_node_t *node)
{
  sukat_tree_node_t *iter = node;

  while (iter->left)
    {
      iter = iter->left;
    }
  return iter;
}

static sukat_tree_node_t *binary_successor(sukat_tree_node_t *node)
{
  if (node && node->right)
    {
      return binary_minimum(node->right);
    }
  return NULL;
}

static sukat_tree_node_t *binary_detach(sukat_tree_ctx_t *ctx,
                                        sukat_tree_node_t *node)
{
  sukat_tree_node_t *ret = NULL;

  if (ctx && node)
    {
      sukat_tree_node_t **parents_ptr = parent_ptr_get(ctx, node);

      node->removed = true;

      if (!node->left || !node->right)
        {
          sukat_tree_node_t *new_child = (node->left) ? node->left :
            node->right;

          if (new_child)
            {
              new_child->parent = node->parent;
            }
          *parents_ptr = new_child;
          ret = node->parent;
        }
      else
        {
          sukat_tree_node_t *successor = binary_successor(node);
          sukat_tree_node_t **successor_parents_ptr;

          assert(successor != NULL);

          ret = (successor->parent == node) ? successor : successor->parent;
          successor_parents_ptr = parent_ptr_get(ctx, successor);
          *parents_ptr = successor;
          *successor_parents_ptr = successor->right;
          if (successor->right)
            {
              successor->right->parent = successor->parent;
            }
          successor->parent = node->parent;
          successor->right = node->right;
          if (successor->right)
            {
              successor->right->parent = successor;
            }
          successor->left = node->left;
          if (successor->left)
            {
              successor->left->parent = successor;
            }
        }
    }
  return ret;
}

void sukat_tree_remove(sukat_tree_ctx_t *ctx, sukat_tree_node_t *node)
{
  sukat_tree_node_t *update_from = binary_detach(ctx, node);

  if (update_from && !ctx->destroyed)
    {
      height_update_up(update_from, true);
    }
  node_free(ctx, node);
}

static sukat_tree_node_t *binary_find(sukat_tree_ctx_t *ctx,
                                      sukat_tree_node_t *node, void *key)
{
  if (node)
    {
      int cmp_val = ctx->cbs.cmp_cb(key, sukat_tree_node_data(node), true);

      if (!cmp_val)
        {
          return node;
        }
      if (cmp_val < 0)
        {
          return binary_find(ctx, node->left, key);
        }
      return binary_find(ctx, node->right, key);
    }
  return NULL;
}

sukat_tree_node_t *sukat_tree_find(sukat_tree_ctx_t *ctx, void *key)
{
  return binary_find(ctx, ctx->head, key);
}

sukat_tree_node_t *sukat_tree_add(sukat_tree_ctx_t *ctx, void *data)
{
  sukat_tree_node_t *node = binary_insert(ctx, data);

  if (!node)
    {
      return NULL;
    }
  height_update_up(node, true);
  // TODO: balance.

  return node;
};

static bool node_df_cb(sukat_tree_node_t *node, void *caller_data)
{
  sukat_tree_ctx_t *ctx = (sukat_tree_ctx_t *)caller_data;
  binary_detach(ctx, node);
  node_free(ctx, node);
  return true;
}

static void depth_first_step(sukat_tree_ctx_t *ctx, sukat_tree_node_cb node_cb,
                             void *caller_ctx, sukat_tree_node_t *node)
{
  if (node)
    {
      depth_first_step(ctx, node_cb, caller_ctx, node->left);
      depth_first_step(ctx, node_cb, caller_ctx, node->right);
      if (node_cb)
        {
          node_cb(node, caller_ctx);
        }
    }
}

void sukat_tree_depth_first(sukat_tree_ctx_t *ctx, sukat_tree_node_cb node_cb,
                            void *caller_ctx)
{
  if (ctx)
    {
      depth_first_step(ctx, node_cb, caller_ctx, ctx->head);
    }
}

void sukat_tree_destroy(sukat_tree_ctx_t *ctx)
{
  DBG(ctx, "Destroying tree %p", ctx);
  ctx->destroyed = true;
  sukat_tree_depth_first(ctx, node_df_cb, ctx);
  free(ctx);
}

/*! }@ */
