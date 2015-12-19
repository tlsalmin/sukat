/*!
 * @file binary_tree.c
 * @brief Binary tree implementation.
 *
 * @addtogroup sukat_tree
 * @{
 */

#include <stdlib.h>
#include <assert.h>
#include "sukat_log_internal.h"
#include "tree_binary.h"

sukat_tree_node_t **tree_binary_parents_ptr(sukat_tree_ctx_t *tree,
                                            sukat_tree_node_t *node)
{
  if (!node->parent)
    {
      return &tree->head;
    }
  return (node->parent->left == node) ?
    &node->parent->left : &node->parent->right;
}

sukat_tree_node_t *tree_binary_insert(sukat_tree_ctx_t *ctx, void *data)
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

  DBG(ctx, "Inserted node %p", *parents_ptr);

  return *parents_ptr;
}

sukat_tree_node_t *tree_binary_minimum(sukat_tree_node_t *node)
{
  sukat_tree_node_t *iter = node;

  while (iter->left)
    {
      iter = iter->left;
    }
  return iter;
}

sukat_tree_node_t *tree_binary_successor(sukat_tree_node_t *node)
{
  if (node && node->right)
    {
      return tree_binary_minimum(node->right);
    }
  return NULL;
}

sukat_tree_node_t *tree_binary_detach(sukat_tree_ctx_t *ctx,
                                      sukat_tree_node_t *node)
{
  sukat_tree_node_t *ret = NULL;

  DBG(ctx, "Detaching node %p", node);
  if (ctx && node)
    {
      sukat_tree_node_t **parents_ptr = tree_binary_parents_ptr(ctx, node);

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
          sukat_tree_node_t *successor = tree_binary_successor(node);
          sukat_tree_node_t **successor_parents_ptr;

          assert(successor != NULL);

          ret = (successor->parent == node) ? successor : successor->parent;
          successor_parents_ptr = tree_binary_parents_ptr(ctx, successor);
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

void tree_binary_rotate_left(sukat_tree_ctx_t *tree, sukat_tree_node_t *node)
{
  sukat_tree_node_t **parents_ptr, *right;
  assert(tree != NULL && node != NULL && node->right != NULL);

  parents_ptr = tree_binary_parents_ptr(tree, node);
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
}

void tree_binary_rotate_right(sukat_tree_ctx_t *tree, sukat_tree_node_t *node)
{
  sukat_tree_node_t **parents_ptr, *left;
  assert(tree != NULL && node != NULL && node->left != NULL);

  parents_ptr = tree_binary_parents_ptr(tree, node);
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
}

sukat_tree_node_t *tree_binary_find(sukat_tree_ctx_t *ctx,
                                    sukat_tree_node_t *node, void *key)
{
  if (node)
    {
      int cmp_val = ctx->cbs.cmp_cb(key, binary_tree_node_data(node), true);

      if (!cmp_val)
        {
          return node;
        }
      if (cmp_val < 0)
        {
          return tree_binary_find(ctx, node->left, key);
        }
      return tree_binary_find(ctx, node->right, key);
    }
  return NULL;
}

static void depth_first_step(sukat_tree_ctx_t *ctx, sukat_drawer_node_cb node_cb,
                             void *caller_ctx, sukat_tree_node_t *node)
{
  if (node)
    {
      depth_first_step(ctx, node_cb, caller_ctx, node->left);
      depth_first_step(ctx, node_cb, caller_ctx, node->right);
      if (node_cb)
        {
          node_cb((sukat_drawer_node_t *)node, caller_ctx);
        }
    }
}

void tree_binary_depth_first(sukat_tree_ctx_t *ctx, sukat_drawer_node_cb node_cb,
                             void *caller_ctx)
{
  if (ctx)
    {
      depth_first_step(ctx, node_cb, caller_ctx, ctx->head);
    }
}

void *binary_tree_node_data(sukat_tree_node_t *node)
{
  if (node)
    {
      return node->data;
    }
  return NULL;
}

void tree_binary_node_free(sukat_tree_ctx_t *ctx, sukat_tree_node_t *node)
{
  if (ctx->cbs.destroy_cb && !node->removed)
    {
      ctx->cbs.destroy_cb(binary_tree_node_data(node));
    }
  free(node);
}

static bool node_df_cb(sukat_drawer_node_t *dnode, void *caller_data)
{
  sukat_tree_node_t *node = (sukat_tree_node_t *)dnode;
  sukat_tree_ctx_t *ctx = (sukat_tree_ctx_t *)caller_data;
  tree_binary_detach(ctx, node);
  tree_binary_node_free(ctx, node);
  return true;
}

void tree_binary_destroy(sukat_tree_ctx_t *ctx)
{
  DBG(ctx, "Destroying tree %p", ctx);
  ctx->destroyed = true;
  tree_binary_depth_first(ctx, node_df_cb, ctx);
  free(ctx);
}

/*! }@ */
