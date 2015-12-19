/*!
 * @file binary_tree.h
 * @brief Binary tree function declarations.
 *
 * @defgroup sukat_tree
 * @ingroup sukat_api
 * @{
 */

#ifndef SUKAT_BINARY_TREE_H
#define SUKAT_BINARY_TREE_H

#include <stdbool.h>
#include "sukat_tree.h"

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

/*!
 * Gets the pointer pointing to the current \p node from its parent or
 * the tree head pointer if the node is the trees root.
 *
 * @param ctx   Tree context.
 * @param node  Node for which pointer is requests.
 *
 * @return != NULL      Parents pointer to \p node
 */
sukat_tree_node_t **tree_binary_parents_ptr(sukat_tree_ctx_t *tree,
                                            sukat_tree_node_t *node);

/*!
 * @brief Inserts \p data into the binary tree, creating a new node.
 *
 * @param ctx   Tree context.
 * @param data  Data to add.
 *
 * @return != NULL      Created nodes pointer.
 * @return == NULL      Failure.
 */
sukat_tree_node_t *tree_binary_insert(sukat_tree_ctx_t *ctx, void *data);

/*!
 * @brief Finds the minimum in \p node
 *
 * @param node  Subtree of which minimum is desired
 *
 * @return node Node containing the minimum value.
 * @return NULL \p was null.
 */
sukat_tree_node_t *tree_binary_minimum(sukat_tree_node_t *node);

/*!
 * @brief Returns the successor of \p node, which is the next biggest value.
 *
 * @param node  Node for which to find successor.
 *
 * @return != NULL      Successor of \p node.
 * @return NULL         No successor for \p node.
 */
sukat_tree_node_t *tree_binary_successor(sukat_tree_node_t *node);

/*!
 * @brief Detaches the \p node from \p ctx tree.
 *
 * @param ctx   Tree context.
 * @param node  Node to remove
 *
 * @return != NULL Lowest node affected by change.
 * @return == NULL No effects.
 */
sukat_tree_node_t *tree_binary_detach(sukat_tree_ctx_t *ctx,
                                      sukat_tree_node_t *node);

/*!
 * @brief Rotates the \p node left in the tree.
 *
 * @param tree  Tree context.
 * @param node  Node to rotate
 */
void tree_binary_rotate_left(sukat_tree_ctx_t *tree, sukat_tree_node_t *node);

/*!
 * @brief Rotates the \p node right in the tree.
 *
 * @param tree  Tree context.
 * @param node  Node to rotate
 */
void tree_binary_rotate_right(sukat_tree_ctx_t *tree, sukat_tree_node_t *node);

/*!
 * @brief Finds the node with \p key. If \p node is given, the search is
 * continued from \p node and not from root.
 *
 * @param ctx   Tree context.
 * @param node  Optional start of search
 * @param key   Key to search for.
 *
 * @return != NULL      Found node.
 * @return == NULL      No node with \p key found
 */
sukat_tree_node_t *tree_binary_find(sukat_tree_ctx_t *ctx,
                                    sukat_tree_node_t *node, void *key);

/*!
 * @brief Performs a depth_first search of the tree calling \p node_cb with
 * \p caller_ctx for each node.
 *
 * @param ctx           Tree context.
 * @param node_cb       Callback to invoke for each node.
 * @param caller_ctx    Context given to caller on each node
 */
void tree_binary_depth_first(sukat_tree_ctx_t *ctx, sukat_tree_node_cb node_cb,
                             void *caller_ctx);

#endif /* SUKAT_BINARY_TREE_H */

