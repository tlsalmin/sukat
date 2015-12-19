/*!
 * @file binary_tree.h
 * @brief Binary tree function declarations.
 *
 * @defgroup tree_binary
 * @ingroup sukat_drawer
 * @{
 */

#ifndef SUKAT_BINARY_TREE_H
#define SUKAT_BINARY_TREE_H

#include <stdbool.h>
#include "sukat_drawer.h"

typedef struct tree_ctx tree_ctx_t;
typedef struct tree_node_ctx tree_node_t;

/*!
 * Main context for a tree.
 */
struct tree_ctx
{
  enum sukat_drawer_type type; //!< Type mandatory at each drawer type start.
  tree_node_t *root; //!< Root of tree.
  struct sukat_drawer_params params;
  struct sukat_drawer_cbs cbs;
  bool destroyed; //!< True if destroy has been called for the tree.
};

/*!
 * Main context for each node
 */
struct tree_node_ctx
{
  enum sukat_drawer_type type; //!< Type mandatory at each drawer type start.
  tree_node_t *parent; //!< Parent node.
  tree_node_t *left; //!< Left == smaller value node.
  tree_node_t *right; //!< Right == larger value node.
  bool removed; /*!< True if this has been explicitly removed. destroyed_cb
                     wont be called */
  union
    {
      int height;
    } meta;
  void *data;
};

/*!
 * Gets the pointer pointing to the current \p node from its parent or
 * the tree root pointer if the node is the trees root.
 *
 * @param ctx   Tree context.
 * @param node  Node for which pointer is requests.
 *
 * @return != NULL      Parents pointer to \p node
 */
tree_node_t **tree_binary_parents_ptr(tree_ctx_t *tree,
                                            tree_node_t *node);

/*!
 * @brief Inserts \p data into the binary tree, creating a new node.
 *
 * @param ctx   Tree context.
 * @param data  Data to add.
 *
 * @return != NULL      Created nodes pointer.
 * @return == NULL      Failure.
 */
tree_node_t *tree_binary_insert(tree_ctx_t *ctx, void *data);

/*!
 * @brief Finds the minimum in \p node
 *
 * @param node  Subtree of which minimum is desired
 *
 * @return node Node containing the minimum value.
 * @return NULL \p was null.
 */
tree_node_t *tree_binary_minimum(tree_node_t *node);

/*!
 * @brief Returns the successor of \p node, which is the next biggest value.
 *
 * @param node  Node for which to find successor.
 *
 * @return != NULL      Successor of \p node.
 * @return NULL         No successor for \p node.
 */
tree_node_t *tree_binary_successor(tree_node_t *node);

/*!
 * @brief Detaches the \p node from \p ctx tree.
 *
 * @param ctx   Tree context.
 * @param node  Node to remove
 *
 * @return != NULL Lowest node affected by change.
 * @return == NULL No effects.
 */
tree_node_t *tree_binary_detach(tree_ctx_t *ctx,
                                      tree_node_t *node);

/*!
 * @brief Rotates the \p node left in the tree.
 *
 * @param tree  Tree context.
 * @param node  Node to rotate
 */
void tree_binary_rotate_left(tree_ctx_t *tree, tree_node_t *node);

/*!
 * @brief Rotates the \p node right in the tree.
 *
 * @param tree  Tree context.
 * @param node  Node to rotate
 */
void tree_binary_rotate_right(tree_ctx_t *tree, tree_node_t *node);

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
tree_node_t *tree_binary_find(tree_ctx_t *ctx,
                                    tree_node_t *node, void *key);

/*!
 * @brief Performs a depth_first search of the tree calling \p node_cb with
 * \p caller_ctx for each node.
 *
 * @param ctx           Tree context.
 * @param node_cb       Callback to invoke for each node.
 * @param caller_ctx    Context given to caller on each node
 */
void tree_binary_depth_first(tree_ctx_t *ctx,
                             sukat_drawer_node_cb node_cb, void *caller_ctx);

/*!
 * @brief \ref sukat_drawer_node_data
 */
void *tree_binary_node_data(tree_node_t *node);

/*!
 * @brief \ref sukat_drawer_destroy
 */
void tree_binary_destroy(tree_ctx_t *ctx);

/*!
 * Frees the given node. Calls destroy_cb if it is set and the node was not
 * explicitly removed.
 *
 * @param ctx   Tree context.
 * @param node  Node context.
 */
void tree_binary_node_free(tree_ctx_t *ctx, tree_node_t *node);

#endif /* SUKAT_BINARY_TREE_H */

