/*!
 * @file sukat_event.h
 * @brief Event loop implementation for the sukat API.
 *
 * @defgroup sukat_event
 * @ingroup sukat_api
 * @{
 *
 * The sukat_event API is used to combine different systems reacting to file
 * descriptors together. By using the sukat_event APIs calls instead of creating
 * separate epolls or manipulating a epoll fd directly, each sukat component can
 * get its desired sukat_event_cb called irrespecive of other elements using
 * the epoll fd.
 *
 * This is especially to address the issue of different components saving
 * different values to the epoll data structure. Also it isn't trivial for
 * the main process evaluating those datas or fds to determine which component
 * should actually continue that processing.
 *
 * TODO: We need a search structure inside sukat_event_ctx to actually free
 * the struct.
 *
 * TODO: add an example in examples/ for using it with pipes.
 */

#ifndef SUKAT_EVENT_H
#define SUKAT_EVENT_H

#include <stdint.h>
#include <stdbool.h>

#include "sukat_log.h"

typedef struct sukat_event_ctx sukat_event_ctx_t;

struct sukat_event_params
{
  int empty; //!< Placeholder for parameters.
};

struct sukat_event_cbs
{
  sukat_log_cb log_cb;
};

/*!
 * Creates an event context.
 *
 * @param log_cb        Logging callback.
 *
 * @return NULL         Failure.
 * @return != NULL      Success. This context should be given to all other
 *                      sukat_event API function.
 */
sukat_event_ctx_t *sukat_event_create(struct sukat_event_params *params,
                                      struct sukat_event_cbs *cbs);

/*!
 * Destroyes the given sukat_event_ctx_t.
 *
 * @param ctx Context to destroy.
 */
void sukat_event_destroy(sukat_event_ctx_t *ctx);

/*!
 * Callback invoked when there is activity in \p fd.
 *
 * @param ctx           caller_ctx passed to \ref sukat_event_add.
 * @param fd            File descriptor with activity.
 * @param events        Epoll events
 */
typedef void (*sukat_event_cb)(void *ctx, int fd, uint32_t events);

/*!
 * Adds \p fd to the event loop.
 *
 * @param ctx           sukat_event API context.
 * @param caller_ctx    Context given to \p cb every time activity is triggered
 *                      in the socket.
 * @param fd            File descriptor to add to event loop
 * @param cb            Callback to invoke when events are readable in the
 *                      socket.
 * @param events        Different events described in man 2 epoll_ctl.
 *
 * @return true         Success.
 * @return false        Failure.
 */
bool sukat_event_add(sukat_event_ctx_t *ctx, void *caller_ctx, int fd,
                     sukat_event_cb cb, uint32_t events);

/*!
 * Removes given fd from the event loop.
 *
 * @param ctx   sukat_event API context.
 * @param fd    File descriptor to remove.
 *
 * @return true         Success.
 * @return false        Failure.
 */
bool sukat_event_remove(sukat_event_ctx_t *ctx, int fd);

/*!
 * Modifies the given fd with new events or parameters
 *
 * \ref sukat_event_add for parameters
 */
bool sukat_event_mod(sukat_event_ctx_t *ctx, void *caller_ctx, int fd,
                     sukat_event_cb cb, uint32_t events);

/*!
 * Reads events from event context.
 *
 * @param ctx           Event context.
 * @param timeout       Time to wait in ms. see man epoll_wait for a description.
 *
 * @return 0    Success.
 * @return != 0 Fatal error.
 */
int sukat_event_read(sukat_event_ctx_t *ctx, int timeout);

#endif /* SUKAT_EVENT_H */

/*! }@ */
