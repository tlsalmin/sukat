/*!
 * @file tree_avl.h
 * @brief Tree structure for storing data.
 *
 * @defgroup tree_avl
 * @ingroup sukat_drawer
 * @{
 */

#ifndef TREE_AVL_H
#define TREE_AVL_H

#include <stdbool.h>
#include "sukat_drawer.h"
#include "tree_binary.h"

/*!
 * @brief Creates an empty AVL tree.
 *
 * @param params        Parameters
 * @param cbs           Callbacks.
 *
 * @return != NULL AVL tree context.
 * @return NULL Failure.
 */
tree_ctx_t *tree_avl_create(struct sukat_drawer_params *params,
                            struct sukat_drawer_cbs *cbs);

/*!
 * @brief Add given \p data to \p tree.
 *
 * @param ctx   Tree to add to.
 * @param data  Data to add.
 *
 * @return != NULL      Created node.
 * @return == NULL      Failure.
 */
tree_node_t *tree_avl_add(tree_ctx_t *ctx, void *data);

/*!
 * @brief Removes node \p node from the AVL-tree.
 *
 * @param ctx   Tree to remove from.
 * @param node  Node to remove
 */
void tree_avl_remove(tree_ctx_t *ctx, tree_node_t *node);

/*!
 * TODO: rename
 */
tree_node_t *sukat_tree_find(tree_ctx_t *ctx, void *key);

#endif /* TREE_AVL_H */

/*! }@ */
