/*!
 * @file sukat_bgp.h
 * @brief BGP library.
 *
 * @defgroup sukat_bgp
 * @ingroup sukat_api
 * @{
 *
 */

#ifndef SUKAT_BGP_H
#define SUKAT_BGP_H

#include <stdint.h>
#include "sukat_log.h"

/*!
 * Main bgp context
 */
typedef struct sukat_bgp_ctx_t sukat_bgp_t;

/*!
 * Client BGP context for each connected client
 */
typedef struct sukat_bgp_client_ctx sukat_bgp_client_t;

/*!
 * @brief Callback invoked for each OPEN message.
 *
 * According to RFC 4271, for each connection between BGP peers a OPEN
 * message is sent, that identifies the peers by their as_num and bgp_id.
 * All values are given here in host byte order.
 *
 * @param ctx           Caller.ctx
 * @param client        BGP client context identifying a client.
 * @param version       BGP version of peer.
 * @param as_num        AS number for peer.
 * @param bgp_id        BGP ID for peer.
 *
 * @return != NULL      New context to be given for each callback. Similar to
 *                      sukat_sock-API conn_cb return value.
 * @return NULL         The caller_ctx given to create will be returned still
 *                      for this client.
 */
typedef void *(*sukat_bgp_open_cb)(void *ctx, sukat_bgp_client_t *client,
                                   uint8_t version, uint16_t as_num,
                                   uint32_t bgp_id);

/*!
 * Parameters for a BGP context.
 */
struct sukat_bgp_params
{
  uint16_t my_as;
  uint32_t bgp_id;
  const char *port; //!< Alternative port. If NULL, RFC default will be used.
  const char *ip; //!< For client mode, the target ip of the other node.
  struct
    {
      uint8_t server:1; //!< True for server.
      uint8_t unused:7;
    };
  void *caller_ctx; //!< Context given to callbacks.
};

/*!
 * Callbacks for a BGP context.
 */
struct sukat_bgp_cbs
{
  sukat_bgp_open_cb open_cb; //!< Callback invoked when OPEN is received.
  sukat_log_cb log_cb;
};

/*!
 * @brief Creates a BGP context.
 *
 * @param params        Parameters.
 * @param cbs           Callbacks.
 *
 * @return != NULL      BGP context used for all other functions.
 * @return NULL         Failure.
 */
sukat_bgp_t *sukat_bgp_create(struct sukat_bgp_params *params,
                              struct sukat_bgp_cbs *cbs);

/*!
 * @brief Destroy BGP context.
 *
 * @param ctx   BGP context.
 */
void sukat_bgp_destroy(sukat_bgp_t *ctx);

/*!
 * @brief Read all activity in the BGP context.
 *
 * \ref sukat_sock_read
 *
 * @return \ref sukat_sock_read
 */
int sukat_bgp_read(sukat_bgp_t *ctx, int timeout);

/*!
 * @brief Disconnect BGP peer.
 *
 * @param ctx           Main BGP context.
 * @param client        Client context
 */
void sukat_bgp_disconnect(sukat_bgp_t *ctx, sukat_bgp_client_t *client);

#endif /* SUKAT_BGP_H */

/*! @} */
