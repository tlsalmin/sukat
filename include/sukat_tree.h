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
 * Removes a node from the tree.
 *
 * @param ctx   Tree context.
 * @param node  Node to remove.
 *
 * @return true         Success.
 * @return false        node not found.
 */
bool sukat_tree_remove(sukat_tree_ctx_t *ctx, sukat_tree_node_t *node);

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
void *sukat_tree_find(sukat_tree_ctx_t *ctx, void *key);

/*!
 * Destroys the given tree, calling the destroy_cb on each node if it is set.
 *
 * @param ctx   Tree to destroy.
 */
void sukat_tree_destroy(sukat_tree_ctx_t *ctx);

#endif /* SUKAT_TREE_H */

/*! }@ */
