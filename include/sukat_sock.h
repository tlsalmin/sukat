/*!
 * @file sukat_sock.h
 * @brief Socket implentation for sukat API.
 *
 * @defgroup sukat_sock
 * @ingroup sukat_api
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

typedef struct sukat_sock_ctx sukat_sock_t;
typedef struct sukat_sock_client_ctx sukat_sock_client_t;

/*!
 * Parameters for type AF_INET.
 */
struct sukat_sock_params_inet
{
  const char *ip;
  const char *port;
};

/*!
 * Parameters for AF_UNIX
 */
struct sukat_sock_params_unix
{
  const char *name;
  bool is_abstract;
};

/*!
 * Parameters for AF_TIPC
 */
struct sukat_sock_params_tipc
{
  uint32_t port_type;
  uint32_t port_instance;
  signed char scope;
};

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
      struct sukat_sock_params_inet pinet;
      struct sukat_sock_params_unix punix;
      struct sukat_sock_params_tipc ptipc;
    };
  int master_epoll_fd; /*!< If ::master_epoll_fd_set is true, the sukat_sock
                            API will add its own epoll fd to this master
                            epoll fd. */
  bool master_epoll_fd_set; //!< If true, use master_epoll_fd
  size_t listen; //!< If non-zero, use for listen parameter (man 2 listen).
};

/*!
 * Callback invoked when the server gets a new connection. Also if set by a
 * client, it will be called after succesfully connecting to the server.
 * In the latter case, the client pointer will be null.
 *
 * @param ctx           Caller context.
 * @param client        Client context that can be replied to.
 * @param sockaddr      Data identifying the connected peer.
 * @param sock_len      The length of the identifying information.
 * @param disconnect    True if an already connected connection was
 *                      disconnected.
 *
 * @return NULL         Continue using this \p ctx for callback involving this
 *                      connection.
 * @return != NULL      A new context to be given each time callbacks are
 *                      that are related to this connection.
 */
typedef void *(*sukat_sock_new_conn_cb)(void *ctx, sukat_sock_client_t *client,
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
 * @param client        Client context. If the msg_cb is invoked on the client,
 *                      this will be NULL.
 * @param buf           Buffer containing message.
 * @param buf_len       Length of message.
 */
typedef void (*sukat_sock_msg_cb)(void *ctx, sukat_sock_client_t *client,
                                  uint8_t *buf, size_t buf_len);

/*!
 * Callback invoked when an error is noticed in a connection. If id == -1,
 * then the error was noticed in the main context (e.g. reading the main fd
 * failed).
 *
 * @param ctx   Caller context. If a custom ctx was set to \p id, then that
 * is returned.
 * @param id    id for which connection failed. -1 for main ctx failure.
 * @param errval error number describing problem
 */
typedef void (*sukat_sock_error_cb)(void *ctx, int id, int errval);

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
  sukat_sock_error_cb error_cb;
};

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
sukat_sock_t *sukat_sock_create(struct sukat_sock_params *params,
                                struct sukat_sock_cbs *cbs);

int sukat_sock_read(sukat_sock_t *ctx, int epoll_fd,
                    uint32_t events, int timeout);

/*!
 * Fetches the slave epoll fd \p ctx is using.
 *
 * @param ctx Sukat API Context.
 *
 * @return >= 0 Sukat API slave epoll fd.
 * @return -1   Error. errno set appropriately.
 */
int sukat_sock_get_epoll_fd(sukat_sock_t *ctx);

/*!
 * Destroyes all sockets and data associated with \p ctx
 *
 * @param ctx   Sukat API context.
 */
void sukat_sock_destroy(sukat_sock_t *ctx);

/*!
 * @brief Disconnects the client.
 *
 * \ref sukat_sock_new_conn_cb will not be called with disconnect == true.
 *
 * @param ctx           Main context.
 * @param client        Client to disconnect.
 */
void sukat_sock_disconnect(sukat_sock_t *ctx, sukat_sock_client_t *client);

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
 * @param id            If non-null, the client to send message to.
 * @param msg           Message to send.
 * @param msg_len       Length of message.
 *
 * @return ::sukat_sock_send_return
 */
enum sukat_sock_send_return sukat_send_msg(sukat_sock_t *ctx,
                                           sukat_sock_client_t *client,
                                           uint8_t *msg, size_t msg_len);

#endif /* SUKAT_SOCK_H */

/*! @} */
