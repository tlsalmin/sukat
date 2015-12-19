/*!
 * @file sukat_tree.h
 * @brief Tree structure for storing data.
 *
 * @defgroup sukat_tree
 * @ingroup sukat_api
 * @{
 */

#include <stdbool.h>
#include "sukat_log.h"

#ifndef SUKAT_TREE_H
#define SUKAT_TREE_H

typedef struct sukat_tree_ctx sukat_tree_ctx_t;

typedef struct sukat_tree_node_ctx sukat_tree_node_t;

/*!
 * Callback function using the callers contexts to determine the 'value' of an
 * entry, which will be used to construct the tree.
 *
 * The 'value' here can be mostly anything as long as its consistant. It could
 * be though as a unique key for the entry. Note that if using the pointer value
 * itself, the find function can never be used. Rather use something inside the
 * data to match your entries.
 *
 * @param n1 Node 1. During a find operation, this will contain the context
 *                   given to the find function.
 * @param n2 Node 2.
 * @param find True if this is a find operation. \ref sukat_tree_find
 *
 * @return 0    Matching element.
 * @return !=   'value' difference between elements.
 */
typedef int (*sukat_tree_cmp_cb)(void *n1, void *n2, bool find);

/*!
 * Optional callback called each time a node is removed from the tree.
 *
 * @param node  Node being removed. This can be free'd.
 */
typedef void (*sukat_tree_destroy_cb)(void *node);

enum sukat_tree_type
{
  SUKAT_TREE_AVL = 0,
};

/*!
 * Parameters used to create a tree
 */
struct sukat_tree_params
{
  enum sukat_tree_type type;
};

struct sukat_tree_cbs
{
  sukat_tree_cmp_cb cmp_cb;
  sukat_tree_destroy_cb destroy_cb;
  sukat_log_cb log_cb;
};

/*!
 * Creates the framework of the tree
 *
 * @param params Parameters for creating a tree.
 *
 * @return != NULL      Success.
 * @return NULL         Failure.
 */
sukat_tree_ctx_t *sukat_tree_create(struct sukat_tree_params *params,
                                    struct sukat_tree_cbs *cbs);

/*!
 * Adds a node to the tree.
 *
 * @param ctx   Tree context.
 * @param data  Data to store.
 *
 * @return != NULL      Success.
 * @return NULL         Failure.
 */
sukat_tree_node_t *sukat_tree_add(sukat_tree_ctx_t *ctx, void *data);

/*!
 * Returns the caller stored data in a node.
 *
 * @param node  Node ctx.
 *
 * @return != NULL Data stored by caller.
 * @return == NULL Error.
 */
void *sukat_tree_node_data(sukat_tree_node_t *node);

/*!
 * @brief Removes a node from the tree.
 *
 * @param ctx   Tree context.
 * @param node  Node to remove.
 */
void sukat_tree_remove(sukat_tree_ctx_t *ctx, sukat_tree_node_t *node);

/*!
 * Finds an entry from the tree.
 *
 * @param ctx           Tree to search.
 * @param key           Key to use for finding. This will be the first parameter
 *                      given to each cmp_cb.
 *
 * @param != NULL       Element found.
 * @param NULL          Element not found.
 */
sukat_tree_node_t *sukat_tree_find(sukat_tree_ctx_t *ctx, void *key);

/*!
 * Callback invoked on each node in searches.
 *
 * @param node Node under iteration.
 * @param caller_data Callers context passed to the search function.
 *
 * @return true Keep iterating.
 * @return false Stop iterating.
 */
typedef bool (*sukat_tree_node_cb)(sukat_tree_node_t *node,
                                   void *caller_data);

/*!
 * @brief Go through the tree in a depth first manner invoking \p node_cb
 * with \p caller_ctx on each node.
 *
 * @param ctx           Tree context.
 * @param node_cb       Callback on invoke on each node.
 * @param caller_ctx    Context to pass for each \p node_cb.h
*/
void sukat_tree_depth_first(sukat_tree_ctx_t *ctx, sukat_tree_node_cb node_cb,
                            void *caller_ctx);

/*!
 * Destroys the given tree, calling the destroy_cb on each node if it is set.
 *
 * @param ctx   Tree to destroy.
 */
void sukat_tree_destroy(sukat_tree_ctx_t *ctx);

#endif /* SUKAT_TREE_H */

/*! }@ */
