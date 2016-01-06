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
#include "sukat_sock.h"

/*!
 * Main bgp context
 */
typedef struct sukat_bgp_ctx_t sukat_bgp_t;

/*!
 * Peer BGP context for each connected peer
 */
typedef struct sukat_bgp_peer_ctx sukat_bgp_peer_t;

/*!
 * Unique parameters identifyind a BGP node
 */
typedef struct bgp_id
{
  uint16_t as_num; //!< AS number.
  uint32_t bgp_id; //!< BGP ID.
  uint8_t version; //!< Version negotiated.
} bgp_id_t;

/*!
 * @brief Callback invoked for each OPEN message.
 *
 * According to RFC 4271, for each connection between BGP peers a OPEN
 * message is sent, that identifies the peers by their as_num and bgp_id.
 * All values are given here in host byte order.
 *
 * @param ctx           Caller.ctx
 * @param peer          BGP peer context identifying a peer.
 * @param id            Unique BGP identifier.
 * @param event         Event the peer caused.
 *
 * @return != NULL      New context to be given for each callback. Similar to
 *                      sukat_sock-API conn_cb return value.
 * @return NULL         The caller_ctx given to create will be returned still
 *                      for this client.
 */
typedef void *(*sukat_bgp_open_cb)(void *ctx, sukat_bgp_peer_t *peer,
                                   bgp_id_t *id, sukat_sock_event_t event);

/*!
 * Parameters for a BGP context.
 */
struct sukat_bgp_params
{
  bgp_id_t id; //!< Own ID. Version doesn't need filling.
  struct sukat_sock_params_inet pinet;
  int master_epoll_fd;
  struct
    {
      uint8_t master_epoll_set:1;
      uint8_t unused:6;
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
 * @briefs Connects to \p peer
 *
 * @param ctx   Main BGP context.
 * @param pinet End-point identifier for peer.
 *
 * @return true         Success.
 * @return false        Failure.
 */
sukat_bgp_peer_t *sukat_bgp_peer_add(sukat_bgp_t *ctx,
                                     struct sukat_sock_params_inet *pinet);

/*!
 * @brief Get the epoll context sukat_bgp is using
 *
 * @param ctx   BGP context.
 *
 * @return epoll fd
 */
int sukat_bgp_get_epoll(sukat_bgp_t *ctx);

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
 * @param peer          Client context
 */
void sukat_bgp_disconnect(sukat_bgp_t *ctx, sukat_bgp_peer_t *peer);

#endif /* SUKAT_BGP_H */

/*! @} */
