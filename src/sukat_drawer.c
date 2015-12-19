/*!
 * @file sukat_drawer.c
 * @brief Implementation of drawer for sukat toolkit.
 *
 * @addtogroup sukat_drawer
 * @{
 */

#include <stdio.h>
#include "sukat_log_internal.h"
#include "sukat_drawer.h"
#include "sukat_tree.h"
#include "tree_binary.h"

sukat_drawer_t *sukat_drawer_create(struct sukat_drawer_params *params,
                                    struct sukat_drawer_cbs *cbs)
{
  if (params->type == SUKAT_DRAWER_TREE_AVL)
    {
      return (sukat_drawer_t *)sukat_tree_create(params, cbs);
    }
  return NULL;
}

sukat_drawer_node_t *sukat_drawer_add(sukat_drawer_t *ctx, void *data)
{
  if (ctx)
    {
      enum sukat_drawer_type type = *(enum sukat_drawer_type *)ctx;

      switch (type)
        {
        case SUKAT_DRAWER_TREE_AVL:
          return (sukat_drawer_node_t *)sukat_tree_add((sukat_tree_ctx_t *)ctx,
                                                       data);
          break;
        default:
          break;
        }
    }
  return NULL;
}

void sukat_drawer_remove(sukat_drawer_t *ctx, sukat_drawer_node_t *node)
{
  if (ctx && node)
    {
      enum sukat_drawer_type type = *(enum sukat_drawer_type *)ctx;

      switch (type)
        {
        case SUKAT_DRAWER_TREE_AVL:
          sukat_tree_remove((sukat_tree_ctx_t *)ctx,
                            (sukat_tree_node_t *)node);
          break;
        default:
          break;
        }
    }
}

void *sukat_drawer_node_data(sukat_drawer_node_t *node)
{
  if (node)
    {
      enum sukat_drawer_type type = *(enum sukat_drawer_type *)node;

      switch (type)
        {
        case SUKAT_DRAWER_TREE_AVL:
          return binary_tree_node_data((sukat_tree_node_t *)node);
          break;
        default:
          break;
        }
    }
  return NULL;
}

void sukat_drawer_destroy(sukat_drawer_t *ctx)
{
  if (ctx)
    {
      enum sukat_drawer_type type = *(enum sukat_drawer_type *)ctx;

      switch (type)
        {
        case SUKAT_DRAWER_TREE_AVL:
          tree_binary_destroy((sukat_tree_ctx_t *)ctx);
        default:
        break;
        }
    }
}

void sukat_drawer_iter(sukat_drawer_t *ctx, sukat_drawer_node_cb node_cb,
                       void *caller_ctx)
{
  if (ctx)
    {
      enum sukat_drawer_type type = *(enum sukat_drawer_type *)ctx;

      switch (type)
        {
        case SUKAT_DRAWER_TREE_AVL:
          tree_binary_depth_first((sukat_tree_ctx_t *)ctx, node_cb, caller_ctx);
        default:
        break;
        }
    }
}

/*! }@ */
