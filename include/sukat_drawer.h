/*!
 * @file sukat_drawer.h
 * @brief Data container for the sukat toolkit.
 *
 * @defgroup sukat_drawer
 * @ingroup sukat_api
 * @{
 */

#ifndef SUKAT_DRAWER_H
#define SUKAT_DRAWER_H

#include <stdbool.h>
#include "sukat_log.h"

typedef struct sukat_drawer_ctx sukat_drawer_t;

typedef struct sukat_drawer_node_ctx sukat_drawer_node_t;

/*!
 * @brief Compare function needed for any tree type.
 *
 * Callback function using the callers contexts to determine the 'value' of an
 * entry, which will be used to construct a tree.
 *
 * The 'value' here can be mostly anything as long as its consistant. It could
 * be though as a unique key for the entry. Note that if using the pointer value
 * itself, the find function can never be used. Rather use something inside the
 * data to match your entries.
 *
 * @param n1 Node 1. During a find operation, this will contain the context
 *                   given to the find function.
 * @param n2 Node 2.
 * @param find True if this is a find operation. \ref sukat_drawer_find
 *
 * @return 0    Matching element.
 * @return !=   'value' difference between elements.
 */
typedef int (*sukat_drawer_cmp_cb)(void *n1, void *n2, bool find);

/*!
 * Optional callback called each time a node is removed from the tree.
 *
 * @param ctx   Context specified in params.
 * @param node  Node being removed. This can be free'd.
 */
typedef void (*sukat_drawer_destroy_cb)(void *ctx, void *node);

enum sukat_drawer_type
{
  SUKAT_DRAWER_TREE_AVL = 0,
};

/*!
 * Parameters used to create a drawer
 */
struct sukat_drawer_params
{
  enum sukat_drawer_type type;
  void *destroy_ctx; //!< Context passed to destroy
};

struct sukat_drawer_cbs
{
  sukat_drawer_cmp_cb cmp_cb;
  sukat_drawer_destroy_cb destroy_cb;
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
sukat_drawer_t *sukat_drawer_create(struct sukat_drawer_params *params,
                                    struct sukat_drawer_cbs *cbs);

/*!
 * Adds a node to the drawer.
 *
 * @param ctx   Drawer context.
 * @param data  Data to store.
 *
 * @return != NULL      Success.
 * @return NULL         Failure.
 */
sukat_drawer_node_t *sukat_drawer_add(sukat_drawer_t *ctx, void *data);

/*!
 * @brief Removes a node from the drawer.
 *
 * @param ctx   Drawer context.
 * @param node  Node to remove.
 */
void sukat_drawer_remove(sukat_drawer_t *ctx, sukat_drawer_node_t *node);

/*!
 * Returns the caller stored data in a node.
 *
 * @param node  Node ctx.
 *
 * @return != NULL Data stored by caller.
 * @return == NULL Error.
 */
void *sukat_drawer_node_data(sukat_drawer_node_t *node);

/*!
 * Destroys the given drawer, calling the destroy_cb on each node if it is set.
 *
 * @param ctx   Tree to destroy.
 */
void sukat_drawer_destroy(sukat_drawer_t *ctx);

/*!
 * Callback invoked on each node when iterating through all entries.
 *
 * @param node Node under iteration.
 * @param caller_data Callers context passed to the search function.
 *
 * @return true Keep iterating.
 * @return false Stop iterating.
 */
typedef bool (*sukat_drawer_node_cb)(sukat_drawer_node_t *node,
                                     void *caller_data);

/*!
 * @brief Go through the drawer invoking \p node_cb * with \p caller_ctx on
 * each node.
 *
 * @param ctx           Drawer context.
 * @param node_cb       Callback on invoke on each node.
 * @param caller_ctx    Context to pass for each \p node_cb
*/
void sukat_drawer_iter(sukat_drawer_t *ctx, sukat_drawer_node_cb node_cb,
                       void *caller_ctx);

/*!
 * Finds an entry from the drawer.
 *
 * @param ctx           Drawer to search.
 * @param key           Key to use for finding. This will be the first parameter
 *                      given to each cmp_cb.
 *
 * @param != NULL       Element found.
 * @param NULL          Element not found.
 */
sukat_drawer_node_t *sukat_drawer_find(sukat_drawer_t *ctx, void *key);



#endif /* !SUKAT_DRAWER_H */

/*! }@ */
