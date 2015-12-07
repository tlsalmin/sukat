/*!
 * @file sukat_sock.h
 * @brief Socket implentation for sukat API.
 *
 * @defgroup sukat_sock
 * @ingropup sukat_api
 * @{
 *
 * sukat API can be used to create socket servers and clients with a small
 * amount of API calls. Also all the trouble with non-blocking sockets and using
 * of file descriptors is hidden from the caller, which only gets different
 * callbacks informing of new clients, messages, disconnects.
 *
 * TODO: Add something to examples/
 */
#ifndef SUKAT_SOCK_H
#define SUKAT_SOCK_H

#include <stdbool.h>
#include <sys/socket.h>
#include <stdint.h>

#include "sukat_log.h"
#include "sukat_event.h"

/*!
 * Parameters for \ref sukat_sock_create
 */
struct sukat_sock_params
{
  void *caller_ctx; //!< Context passed to callbacks.
  bool server; //!< If true, act as server.
  int domain; //!< AF_UNIX, AF_UNSPEC(AF_INET or AF_INET6) or AF_TIPC
  int type; //!< SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET or SOCK_RDM.
  union
    {
      const char *ip; //!< AF_UNSPEC: The IP to connect/bind to.
      const char *name; //!< AF_UNIX: Path or abstract name.
      uint32_t port_type; //!< AF_TIPC: port type.
    } id;
  union
    {
      const char *port; //!< Port for AF_UNSPEC.
      bool abstract; //!< If true on AF_UNIx, use abstract domain sockets.
      uint32_t port_instance; //!< Port instance for AF_TIPC.
    } specific;
  sukat_event_ctx_t *event_ctx; /*! If set, the sukat_event_ctx to use for all
                                    file descriptors created from this
                                    sukat_sock_ctx.  If NULL, the sukat API will
                                    create its own sukat_event_ctx */
  size_t listen; //!< If non-zero, use for listen parameter (man 2 listen).
};

/*!
 * Callback invoked when the server gets a new connection. Also if set by a
 * client, it will be called after succesfully connecting to the server.
 *
 * @param ctx           Caller context.
 * @param sockaddr      Data identifying the connected peer.
 * @param id            Unique identifier for client that can be used by the
 *                      server to identify a client when sending messages.
 * @param sock_len      The length of the identifying information.
 * @param disconnect    True if an already connected connection was
 *                      disconnected.
 *
 * @return NULL         Continue using this \p ctx for callback involving this
 *                      connection.
 * @return != NULL      A new context to be given each time callbacks are
 *                      that are related to this connection.
 */
typedef void *(*sukat_sock_new_conn_cb)(void *ctx, int id,
                                        struct sockaddr_storage *sockaddr,
                                        size_t sock_len, bool disconnect);

/*!
 * Callback invoked each time anything longer than 1 byte is received from a
 * connection. The callback should return the number of bytes expected from
 * the given message. If that number can't yet be determined, it should return
 * 0. If there is a clear corruption visible in the message a negative value
 * should be returned.
 *
 * @param ctx           Caller ctx.
 * @param buf           Buffer containing message.
 * @param buf_len       Length of data in buffer.
 *
 * @return > 0          Length of the whole message.
 * @return 0            Length not yet deducable.
 * @return < 0          Corruption.
 */
typedef int (*sukat_sock_msg_len_cb)(void *ctx, uint8_t *buf, size_t buf_len);

/*!
 * Callback invoked each time a full message is received.
 *
 * @param ctx           Caller context.
 * @param id            Unique client id.
 * @param buf           Buffer containing message.
 * @param buf_len       Length of message.
 */
typedef void (*sukat_sock_msg_cb)(void *ctx, int id, uint8_t buf,
                                  size_t buf_len);

/*!
 * Different callbacks invoked by the library, initializable by the caller
 * in sukat_sock_create.
 */
struct sukat_sock_cbs
{
  sukat_log_cb log_cb;
  sukat_sock_new_conn_cb conn_cb;
  sukat_sock_msg_len_cb msg_len_cb;
  sukat_sock_msg_cb msg_cb;
};

typedef struct sukat_sock_ctx sukat_sock_ctx_t;

/*!
 * Create function for a socket.
 *
 * @param params        Parameters to socket.
 * @param cbs           Callbacks invoked by the library.
 *
 * @return NULL         Failure.
 * @return != NULL      Sukat context, which should be passed to all later sukat
 *                      API calls
 */
sukat_sock_ctx_t *sukat_sock_create(struct sukat_sock_params *params,
                                    struct sukat_sock_cbs *cbs);

/*!
 * Destroyes all sockets and data associated with \p ctx
 *
 * @param ctx   Sukat API context.
 */
void sukat_sock_destroy(sukat_sock_ctx_t *ctx);

/*!
 * Different possible return values for sukat API send calls.
 */
enum sukat_sock_send_return
{
  SUKAT_SEND_ERROR = -1, /*! Fatal connection error in sending */
  SUKAT_SEND_OK = 0, /*!< Data sent okay. Part of data might be cached due to
                          congestion */
  SUKAT_SEND_EAGAIN //!< Whole message dropped due to congestion
};

/*!
 * Sends a message. In case the sukat context is a server, a client is
 * identified by \p id. Otherwise \p id is ignored and the message is sent to
 * the server.
 *
 * @param ctx           Sukat API context.
 * @param id            Unique ID for client received in \ref sukat_sock_new_conn_cb
 * @param msg           Message to send.
 * @param msg_len       Length of message.
 *
 * @return ::sukat_sock_send_return
 */
enum sukat_sock_send_return sukat_send_msg(sukat_sock_ctx_t *ctx, int id,
                                           uint8_t *msg, size_t msg_len);

#endif /* SUKAT_SOCK_H */

/*! @} */
