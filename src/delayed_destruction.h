/*!
 * @file delayed_destruction.h
 * @brief Helper for operating with callbacks and heap-memory.
 *
 * @defgroup delayed_destruction
 * @ingroup sukat_api
 * @{
 */

#ifndef DELAYED_DESTRUCTION_H
#define DELAYED_DESTRUCTION_H

#include <stdbool.h>
#include <stdint.h>
#include "sukat_log_internal.h"

/*!
 * Struct that needs to be in front of each context using delayed destruction.
 */
typedef struct destro_client_hook
{
  struct destro_client_hook *next;
  struct
    {
      uint8_t destroyed:1;
      uint8_t closed:1;
      uint8_t unused:6;
    };
} destro_client_t;

typedef struct destro_ctx destro_t;

/*!
 * @brief callback used when its safe to close context.
 *
 * @param main_ctx      Main context.
 * @param client_ctx    If non-null: Client context to close.
 *                      Otherwise main_ctx is the one needing close.
 */
typedef void (*destro_close)(void *main_ctx, void *client_ctx);

/*!
 * @brief Callback invoked when its safe to free client_ctx or main_ctx
 *
 * @param main_ctx      Main context.
 * @param client_ctx    If non-null: client to free.
 *                      Otherwise main_ctx should be freed
 */
typedef void (*destro_free)(void *main_ctx, void *client_ctx);

struct destro_cbs
{
  sukat_log_cb log_cb;
  destro_close close;
  destro_free dfree; //!< If NULL, regular free will be used
};

struct destro_params
{
  void *main_ctx; //!< Main context passed to callbacks.
};

/*!
 * @brief Creates a destro context.
 *
 * @param params        Parameters for destro.
 * @param cbs           Callbacks for destro.
 *
 * @return != NULL      Context for destro-functions.
 * @return NULL         Error
 */
destro_t *destro_create(struct destro_params *params, struct destro_cbs *cbs);

/*!
 * @brief Inform destro we're entering the callback zone.
 *
 * This will cause deletions to be delayed until the callback zone is returned
 * from.
 *
 * @param ctx           Destroy context
 */
void destro_cb_enter(destro_t *ctx);

/*!
 * @brief Inform destro we're leaving the callback zone.
 *
 * This will cause any delayed deletions to occur.
 *
 * @param ctx           Destroy context
 * @param client_ctx    Optional client context if callback is tracked in client
 *                      level.
 */
void destro_cb_exit(destro_t *ctx);

/*!
 * @brief Invokes close and free on the target.
 *
 * Depending if we're in a callback or not, this will close and free the
 * target. The target being client_ctx if it is set or the main_ctx given
 * in params if client_ctx == NULL.
 *
 * @param ctx   Destroy context.
 */
void destro_delete(destro_t *ctx, destro_client_t *client);

/*!
 * @brief Checks if main ctx or client has been deleted
 *
 * Checks if main context or the optional client_ctx has been destroyed.
 *
 * @param ctx           Destro context.
 * @param client        Destro client context.
 *
 * @return true         Yes. Should probably exit em' loops.
 * @return false        No. All is OK.
 */
bool destro_is_deleted(destro_t *ctx, destro_client_t *client);

/*!
 * Notice that no destro_destroy is given as it will delete itself when
 * destro_delete is called with a NULL client_ctx and the callback zone
 * has been returned from.
 */

#endif /* !DELAYED_DESTRUCTION_H */

/*! @} */
