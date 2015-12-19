/*!
 * @file sukat_tree.h
 * @brief Tree structure for storing data.
 *
 * @defgroup sukat_tree
 * @ingroup sukat_drawer
 * @{
 */

#ifndef SUKAT_TREE_H
#define SUKAT_TREE_H

#include <stdbool.h>
#include "sukat_log.h"
#include "sukat_drawer.h"

typedef struct sukat_tree_ctx sukat_tree_ctx_t;

typedef struct sukat_tree_node_ctx sukat_tree_node_t;

sukat_tree_ctx_t *sukat_tree_create(struct sukat_drawer_params *params,
                                    struct sukat_drawer_cbs *cbs);

/*!
 * @brief Go through the tree in a depth first manner invoking \p node_cb
 * with \p caller_ctx on each node.
 *
 * @param ctx           Tree context.
 * @param node_cb       Callback on invoke on each node.
 * @param caller_ctx    Context to pass for each \p node_cb
*/
void sukat_tree_depth_first(sukat_tree_ctx_t *ctx, sukat_drawer_node_cb node_cb,
                            void *caller_ctx);

sukat_tree_node_t *sukat_tree_add(sukat_tree_ctx_t *ctx, void *data);

void sukat_tree_remove(sukat_tree_ctx_t *ctx, sukat_tree_node_t *node);

#endif /* SUKAT_TREE_H */

/*! }@ */
