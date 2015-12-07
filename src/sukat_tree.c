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
};

struct sukat_tree_node_ctx
{
  sukat_tree_node_t *parent;
  sukat_tree_node_t *left;
  sukat_tree_node_t *right;
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

static void height_update_up(sukat_tree_node_t *node)
{
  height_count(node);
  node = node->parent;
  while (node)
    {
      height_count(node);
      node = node->parent;
    }
}

static void rotate_left(sukat_tree_ctx_t *tree, sukat_tree_node_t *node)
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

  /* Update heights. */
  height_update_up(node);
}

static void rotate_right(sukat_tree_ctx_t *tree, sukat_tree_node_t *node)
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

  /* Update heights. */
  height_update_up(node);
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
  while (parent)
    {
      height_count(parent);
      parent = parent->parent;
    }

  return *parents_ptr;
}

sukat_tree_node_t *sukat_tree_add(sukat_tree_ctx_t *ctx, void *data)
{
  sukat_tree_node_t *node = binary_insert(ctx, data);

  if (!node)
    {
      return NULL;
    }
  // TODO: balance.

  return node;
};

void sukat_tree_destroy(sukat_tree_ctx_t *ctx)
{
  //TODO: Remove nodes.
  free(ctx);
  DBG(ctx, "Destroyed tree %p", ctx);
}

/*! }@ */
