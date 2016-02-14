#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <unistd.h>
#endif
#include <iostream>
#include <fstream>
#include <random>
#include <string>

#include "gtest/gtest.h"
#include "test_common.h"

extern "C"{
#include "sukat_log_internal.c"
#include "sukat_sock.c"
#include "sukat_event.h"
#include <stdlib.h>
#include <sys/un.h>
}

void get_random_socket(char *where, size_t length)
{
  int fd;
  snprintf(where, length,
           "/tmp/sukat_sock_sun_test_XXXXXX");

  fd = mkstemp(where);
  ASSERT_NE(-1, fd);
  close(fd);
  unlink(where);
}

class sukat_sock_test_tipc : public ::testing::Test
{
protected:
  // You can remove any or all of the following functions if its body is empty.

  sukat_sock_test_tipc() {
      // You can do set-up work for each test here.
  }

  virtual ~sukat_sock_test_tipc() {
      // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up and
  // cleaning up each test, you can define the following methods:
  virtual void SetUp() {
      memset(&default_cbs, 0, sizeof(default_cbs));
      memset(&default_endpoint_params, 0, sizeof(default_endpoint_params));
      default_cbs.log_cb = test_log_cb;
      memset(&default_params, 0, sizeof(default_params));
      // Code here will be called immediately after the constructor (right
      // before each test).
  }

  virtual void TearDown() {
      // Code here will be called immediately after each test (right
      // before the destructor).
  }
  void get_random_port(struct sukat_sock_endpoint_params *params)
    {
      static bool random_seeded;

      if (!random_seeded)
        {
          FILE *urandom = fopen("/dev/urandom", "r");
          unsigned int seed;
          size_t n_read;

          EXPECT_NE(nullptr, urandom);
          n_read = fread(&seed, sizeof(seed), 1, urandom);
          EXPECT_EQ(1, n_read);
          fclose(urandom);

          srand(seed);

          random_seeded = true;
        }

      params->ptipc.port_type = 63 + ((uint32_t)rand() % UINT32_MAX);
      params->ptipc.port_instance = ((uint32_t)rand() % UINT32_MAX);
      params->ptipc.scope = TIPC_NODE_SCOPE;
    }
  bool check_tipc()
    {
      std::ifstream procfile("/proc/modules");
      char buf[128];

      if (procfile.is_open())
        {
          std::string line;

          while (getline(procfile, line))
            {
              if (line.find("tipc") != std::string::npos)
                {
                  procfile.close();
                  return true;
                }
            }
          procfile.close();
        }
      snprintf(buf, sizeof(buf), "Failed to check for TIPC: %s",
               strerror(errno));
      default_cbs.log_cb(SUKAT_LOG_ERROR, buf);
      return false;
    }

  bool wait_for_tipc_server(sukat_sock_t *ctx, uint32_t name_type,
                            uint32_t name_instance, int wait)
    {
      struct sockaddr_tipc topsrv = { };
      struct tipc_subscr subscr= { };
      struct tipc_event event = { };

      int sd = socket(AF_TIPC, SOCK_SEQPACKET, 0);

      memset(&topsrv, 0, sizeof(topsrv));
      topsrv.family = AF_TIPC;
      topsrv.addrtype = TIPC_ADDR_NAME;
      topsrv.addr.name.name.type = TIPC_TOP_SRV;
      topsrv.addr.name.name.instance = TIPC_TOP_SRV;

      /* Connect to topology server */

      if (0 > connect(sd, (struct sockaddr *)&topsrv, sizeof(topsrv))) {
          ERR(ctx, "Client: failed to connect to topology server: %S",
              strerror(errno));
          return false;
      }

      subscr.seq.type = htonl(name_type);
      subscr.seq.lower = htonl(name_instance);
      subscr.seq.upper = htonl(name_instance);
      subscr.timeout = htonl(wait);
      subscr.filter = htonl(TIPC_SUB_SERVICE);

      if (send(sd, &subscr, sizeof(subscr), 0) != sizeof(subscr)) {
          ERR(ctx, "Client: failed to send subscription: %s",strerror(errno));
          return false;
      }
      /* Now wait for the subscription to fire */

      if (recv(sd, &event, sizeof(event), 0) != sizeof(event)) {
          ERR(ctx, "Client: failed to receive event: %s", strerror(errno));
          return false;
      }
      if (event.event != htonl(TIPC_PUBLISHED)) {
          ERR(ctx, "Client: server {%u,%u} not published within %u [s]\n: %s",
                 name_type, name_instance, wait/1000, strerror(errno));
          return false;
      }
      LOG(ctx, "Server published TIPC!");

      close(sd);
      return true;
    }

  // Objects declared here can be used by all tests
  struct sukat_sock_cbs default_cbs;
  struct sukat_sock_params default_params;
  struct sukat_sock_endpoint_params default_endpoint_params;
};

struct test_ctx
{
  int yeah;
};

TEST_F(sukat_sock_test_tipc, sukat_sock_test_tipc)
{
  sukat_sock_t *ctx, *client_ctx;
  sukat_sock_endpoint_t *server_endpoint, *client_endpoint;
  struct test_ctx tctx = { };
  bool bret;
  int err;

  default_params.caller_ctx = &tctx;
  default_endpoint_params.server = true;
  default_endpoint_params.domain = AF_TIPC;
  default_endpoint_params.type = SOCK_SEQPACKET;

  get_random_port(&default_endpoint_params);

  if (check_tipc() == false)
    {
      default_cbs.log_cb(SUKAT_LOG,
                         "Skipping TIPC socket. modprobe tipc to enable");
      return;
    }

  ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);
  server_endpoint = sukat_sock_endpoint_add(ctx, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);

  default_endpoint_params.server = false;
  bret = wait_for_tipc_server(ctx, default_endpoint_params.ptipc.port_type,
                              default_endpoint_params.ptipc.port_instance, 1000);
  EXPECT_EQ(true, bret);

  client_ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client_ctx);
  client_endpoint =
    sukat_sock_endpoint_add(client_ctx, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);

  err = sukat_sock_read(ctx, 0);
  EXPECT_NE(-1, err);

  sukat_sock_disconnect(client_ctx, client_endpoint);
  sukat_sock_destroy(client_ctx);
  err = sukat_sock_read(ctx, 0);
  EXPECT_NE(-1, err);

  sukat_sock_disconnect(ctx, server_endpoint);
  sukat_sock_destroy(ctx);
}

class sukat_sock_test_sun : public ::testing::Test
{
protected:
  // You can remove any or all of the following functions if its body is empty.

  sukat_sock_test_sun() {
      // You can do set-up work for each test here.
  }

  virtual ~sukat_sock_test_sun() {
      // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up and
  // cleaning up each test, you can define the following methods:
  virtual void SetUp() {
      memset(&default_cbs, 0, sizeof(default_cbs));
      memset(&default_params, 0, sizeof(default_params));
      memset(&default_endpoint_params, 0, sizeof(default_endpoint_params));

      default_cbs.log_cb = test_log_cb;

      get_random_socket(sun_template, sizeof(sun_template));
      default_endpoint_params.punix.name = sun_template;
      default_endpoint_params.domain = AF_UNIX;
      default_endpoint_params.punix.is_abstract = true;
      default_endpoint_params.type = SOCK_STREAM;
  }

  virtual void TearDown() {
      default_endpoint_params.punix.name = NULL;
      // Code here will be called immediately after each test (right
      // before the destructor).
  }

  // Objects declared here can be used by all tests
  struct sukat_sock_cbs default_cbs;
  struct sukat_sock_params default_params;
  struct sukat_sock_endpoint_params default_endpoint_params;
  char sun_template[sizeof(((struct sockaddr_un *)0)->sun_path) - 2];
};

struct sun_test_ctx
{
  bool connected_should;
  bool connected_visited;
  bool connected_should_disconnect;
  sukat_sock_endpoint_t *newest_client;
  void *new_ctx;
  size_t n_connects;
  size_t n_disconnects;
};

struct test_client
{
  int id;
};

void *new_conn_cb(void *ctx, sukat_sock_endpoint_t *client,
                  sukat_sock_event_t event)
{
  struct sun_test_ctx *tctx = (struct sun_test_ctx *)ctx;

  EXPECT_EQ(true, tctx->connected_should);
  if (event == SUKAT_SOCK_CONN_EVENT_DISCONNECT)
    {
      EXPECT_EQ(true, tctx->connected_should_disconnect);
      tctx->n_disconnects++;
    }
  else
    {
      tctx->n_connects++;
    }
  tctx->newest_client = client;
  tctx->connected_visited = true;
  return tctx->new_ctx;
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_faulty_param)
{
  sukat_sock_t *server;
  sukat_sock_endpoint_t *endpoint;

  // Test with no params
  server = sukat_sock_create(NULL, &default_cbs);
  EXPECT_EQ(nullptr, server);

  // Test peer without main
  endpoint = sukat_sock_endpoint_add(NULL, &default_endpoint_params);
  EXPECT_EQ(nullptr, endpoint);

  server = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, server);

  endpoint = sukat_sock_endpoint_add(server, NULL);
  EXPECT_EQ(nullptr, endpoint);

  sukat_sock_destroy(server);
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_external_epoll)
{
  int master_epoll;
  sukat_sock_t *server;

  // Test with another epoll.
  master_epoll = epoll_create1(EPOLL_CLOEXEC);
  EXPECT_NE(-1, master_epoll);

  // First with a faulty master_epoll.
  default_params.master_epoll_fd_set = true;
  default_params.master_epoll_fd = -1;
  server = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_EQ(nullptr, server);
  get_random_socket(sun_template, sizeof(sun_template));

  default_params.master_epoll_fd = master_epoll;
  server = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, server);
  sukat_sock_destroy(server);
  close(master_epoll);

}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_stream_connect)
{
  sukat_sock_t *server, *client;
  sukat_sock_endpoint_t *server_endpoint, *client_endpoint;
  struct sun_test_ctx tctx = { };
  int err;

  default_params.caller_ctx = &tctx;
  default_cbs.conn_cb = new_conn_cb;

  server = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, server);
  default_endpoint_params.server = true;
  server_endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);

  default_cbs.conn_cb = NULL;
  client = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, server);
  default_endpoint_params.server = false;
  client_endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);

  tctx.connected_should = true;
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.connected_visited);
  EXPECT_EQ(2, server->n_connections);
  tctx.connected_should = tctx.connected_visited = false;

  sukat_sock_disconnect(client, client_endpoint);

  tctx.connected_should = tctx.connected_should_disconnect = true;
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.connected_visited);
  tctx.connected_should = tctx.connected_visited =
    tctx.connected_should_disconnect = false;

  sukat_sock_destroy(client);
  sukat_sock_disconnect(server, server_endpoint);
  sukat_sock_destroy(server);
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_stream_connect_many)
{
  struct sun_test_ctx tctx = { };
  sukat_sock_t *server;
  sukat_sock_endpoint_t *server_endpoint;
  size_t i;
  const size_t n_clients = SOMAXCONN;
  sukat_sock_t *clients[n_clients];
  sukat_sock_endpoint_t *client_endpoints[n_clients];
  int err;

  default_params.caller_ctx = &tctx;
  default_cbs.conn_cb = new_conn_cb;
  server = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, server);
  default_endpoint_params.server = true;
  server_endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);

  default_cbs.conn_cb = NULL;
  default_endpoint_params.server = false;
  for (i = 0; i < n_clients; i++)
    {
      clients[i] = sukat_sock_create(&default_params, &default_cbs);
      EXPECT_NE(nullptr, clients[i]);
      client_endpoints[i] =
        sukat_sock_endpoint_add(clients[i], &default_endpoint_params);
      EXPECT_NE(nullptr, client_endpoints[i]);
    }
  tctx.connected_should = true;
  err = sukat_sock_read(server, 0);
  EXPECT_NE(-1, err);
  EXPECT_EQ(true, tctx.connected_visited);
  EXPECT_EQ(n_clients + 1, server->n_connections);
  EXPECT_EQ(n_clients, tctx.n_connects);
  tctx.connected_should = tctx.connected_visited = false;

  for (i = 0; i < n_clients; i++)
    {
      sukat_sock_disconnect(clients[i], client_endpoints[i]);
      sukat_sock_destroy(clients[i]);
    }
  tctx.connected_should = tctx.connected_should_disconnect = true;
  err = sukat_sock_read(server, 0);
  EXPECT_NE(-1, err);
  EXPECT_EQ(true, tctx.connected_visited);
  EXPECT_EQ(n_clients, tctx.n_disconnects);

  sukat_sock_disconnect(server, server_endpoint);
  sukat_sock_destroy(server);
}

struct read_ctx
{
  sukat_sock_endpoint_t *newest_client;
  struct {
      uint16_t len_cb_should_visit:1;
      uint16_t len_cb_visited:1;
      uint16_t return_corrupt:1;
      uint16_t should_disconnect:1;
      uint16_t connect_visited:1;
      uint16_t msg_cb_should_visit:1;
      uint16_t msg_cb_visited:1;
      uint16_t compare_payload:1;
      uint16_t compared_payload:1;
      uint16_t copy_client:1;
      uint16_t unused:6;
  };
  uint8_t *buf;
  size_t offset;
  size_t n_messages;
};

#pragma pack (1)
struct test_msg
{
  uint64_t type;
  uint64_t len;
  uint8_t data[];
};
#pragma pack (0)

static int len_cb(void *ctx, __attribute__((unused))uint8_t *buf,
                  size_t buf_len)
{
  struct read_ctx *tctx = (struct read_ctx*)ctx;
  struct test_msg *msg = (struct test_msg *)buf;

  EXPECT_NE(nullptr, buf);
  EXPECT_NE(nullptr, tctx);
  tctx->len_cb_visited = true;
  if (tctx->return_corrupt == true)
    {
      return -1;
    }
  if (buf_len < sizeof(*msg))
    {
      return 0;
    }
  return msg->len;
}

static void msg_cb(void *ctx, sukat_sock_endpoint_t *client, uint8_t *buf,
                   size_t buf_len)
{
  struct read_ctx *tctx = (struct read_ctx*)ctx;

  EXPECT_EQ(true, tctx->msg_cb_should_visit);
  tctx->msg_cb_visited = true;
  tctx->newest_client = client;
  if (tctx->compare_payload)
    {
      int compareval;

      compareval = memcmp(buf, tctx->buf + tctx->offset, buf_len);
      EXPECT_EQ(0, compareval);
      tctx->offset += buf_len;
      tctx->compared_payload = true;
    }
  if (tctx->copy_client)
    {
      tctx->newest_client = (sukat_sock_endpoint_t *)malloc(sizeof(*client));
      EXPECT_NE(nullptr, tctx->newest_client);
      memcpy(tctx->newest_client, client, sizeof(*client));
    }
  tctx->n_messages++;
}

void *new_conn_cb_for_read(void *ctx, sukat_sock_endpoint_t *client,
                           sukat_sock_event_t event)
{
  struct read_ctx *tctx = (struct read_ctx *)ctx;
  tctx->newest_client = client;
  if (tctx->should_disconnect)
    {
      EXPECT_EQ(SUKAT_SOCK_CONN_EVENT_DISCONNECT, event);
    }
  tctx->connect_visited = true;
  return NULL;
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_stream_read)
{
  sukat_sock_t *server, *client_ctx;
  sukat_sock_endpoint_t *server_endpoint;
  sukat_sock_endpoint_t *client_from_server;
  sukat_sock_endpoint_t *client_endpoint;
  uint8_t buf[BUFSIZ];
  struct test_msg *msg = (struct test_msg *)buf;
  struct read_ctx tctx = { };
  int err;
  enum sukat_sock_send_return send_ret;
  size_t msg_len = 5000, i, total_sent, total_read;

  default_cbs.msg_len_cb = len_cb;
  default_cbs.conn_cb = new_conn_cb_for_read;
  default_cbs.msg_cb = msg_cb;
  default_endpoint_params.server = true;
  default_params.caller_ctx = (void *)&tctx;
  tctx.buf = buf;
  tctx.compare_payload = true;

  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);
  server_endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);

  default_endpoint_params.server = false;
  client_ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client_ctx);
  client_endpoint =
    sukat_sock_endpoint_add(client_ctx,&default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(2, server->n_connections);
  client_from_server = tctx.newest_client;

  /* Simple single message */
  msg->type = 0;
  msg->len = sizeof(*msg);

  send_ret = sukat_send_msg(client_ctx, client_endpoint, buf, msg->len, NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.len_cb_should_visit = tctx.msg_cb_should_visit = true;
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  EXPECT_EQ(true, tctx.compared_payload);
  tctx.offset = 0;
  tctx.compared_payload = tctx.msg_cb_visited = false;

  /* Reply */
  err = sukat_send_msg(server, client_from_server, buf, msg->len, NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.len_cb_visited = tctx.msg_cb_visited = false;
  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  tctx.offset = 0;

  /* Message that needs caching */
  tctx.len_cb_should_visit = true;
  tctx.msg_cb_should_visit = false;
  tctx.len_cb_visited = tctx.msg_cb_visited = false;

  send_ret =
    sukat_send_msg(server, client_from_server, buf, sizeof(*msg) / 2, NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(false, tctx.msg_cb_visited);
  tctx.offset = 0;

  /* Continue */
  send_ret = sukat_send_msg(server, client_from_server,
                            buf + (sizeof(*msg) / 2), sizeof(*msg) / 2, NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.msg_cb_should_visit = true;
  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  tctx.len_cb_visited = tctx.msg_cb_visited = false;
  tctx.offset = 0;

  /* Longer message */
  memset(buf, 'c', msg_len);
  msg->len = msg_len;
  msg->type = 0;

  /* Send first half */
  send_ret = sukat_send_msg(server, client_from_server, buf, msg_len / 2, NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.msg_cb_should_visit = false;
  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(false, tctx.msg_cb_visited);
  tctx.len_cb_visited = tctx.msg_cb_visited = false;
  tctx.offset = 0;

  /* Send second half */
  send_ret =
    sukat_send_msg(server, client_from_server, buf + (msg_len / 2),
                   msg_len / 2, NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.msg_cb_should_visit = true;
  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  tctx.len_cb_visited = tctx.msg_cb_visited = false;
  tctx.offset = 0;
  tctx.msg_cb_should_visit = tctx.len_cb_should_visit = false;

  /* Send lots of small messages */
  msg_len = 40;
  for (i = 0; i < 100; i++)
    {
      memset(buf + i * msg_len, i, msg_len);
      msg = (struct test_msg *)(buf + i * msg_len);
      msg->type = 0;
      msg->len = msg_len;
      send_ret = sukat_send_msg(server, client_from_server,
                                (uint8_t *)msg, msg->len, NULL);
      EXPECT_EQ(SUKAT_SEND_OK, send_ret);
    }

  tctx.n_messages = 0;
  tctx.msg_cb_should_visit = tctx.len_cb_should_visit = true;

  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  EXPECT_EQ(100, tctx.n_messages);

  /* Send messages until EAGAIN. */
  memset(buf, 0, sizeof(buf));
  msg = (struct test_msg *)(buf);
  msg->type = 0;
  msg->len = sizeof(buf);
  total_sent = 0;
  while ((send_ret =
          sukat_send_msg(server, client_from_server, (uint8_t *)msg,
                         msg->len, NULL)) == SUKAT_SEND_OK)
    {
      total_sent += msg_len;
    }
  EXPECT_EQ(SUKAT_SEND_EAGAIN, send_ret);
  EXPECT_GT(total_sent, 0);

  total_read = 0;
  while ((err = read(client_endpoint->info.fd, buf, sizeof(buf))) > 0)
    {
      total_read += err;
    }
  EXPECT_EQ(-1, err);
  EXPECT_GT(total_read, 0);
  EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);

  /* So somehow I can't get the send side to ever send a partial message
   * I'll just do the send caching test in AF_INET */

  sukat_sock_disconnect(server, client_from_server);
  sukat_sock_disconnect(server, server_endpoint);
  sukat_sock_disconnect(client_ctx, client_endpoint);
  sukat_sock_destroy(client_ctx);
  sukat_sock_destroy(server);
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_seqpacket)
{
  sukat_sock_t *server, *client;
  sukat_sock_endpoint_t *server_endpoint, *server_from_client,
                        *client_from_server;
  struct read_ctx tctx = { };
  int err;
  char buf[BUFSIZ];
  enum sukat_sock_send_return send_ret;

  default_endpoint_params.type = SOCK_SEQPACKET;
  default_cbs.msg_len_cb = len_cb;
  default_cbs.conn_cb = new_conn_cb_for_read;
  default_cbs.msg_cb = msg_cb;
  default_endpoint_params.server = true;
  default_params.caller_ctx = (void *)&tctx;

  server = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, server);
  server_endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);

  default_endpoint_params.server = false;
  client = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, client);
  server_from_client = sukat_sock_endpoint_add(client,
                                               &default_endpoint_params);
  EXPECT_NE(nullptr, client);

  // Accept client
  err = sukat_sock_read(server, 100);
  EXPECT_EQ(0, err);
  EXPECT_NE(nullptr, tctx.newest_client);
  client_from_server = tctx.newest_client;

  snprintf(buf, sizeof(buf), "Hello there new seqpacket client");
  send_ret = sukat_send_msg(server, client_from_server,
                            (uint8_t *)buf, strlen(buf), NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.buf = (uint8_t *)buf;
  tctx.compare_payload = tctx.msg_cb_should_visit = true;
  err = sukat_sock_read(client, 100);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  EXPECT_EQ(0, err);
  tctx.msg_cb_visited = false;
  tctx.offset = 0;

  snprintf(buf, sizeof(buf), "Hello there seqpacket server");
  send_ret = sukat_send_msg(client, server_from_client, (uint8_t *)buf,
                            strlen(buf), NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  err = sukat_sock_read(server, 100);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  EXPECT_EQ(0, err);

  sukat_sock_disconnect(client, client_from_server);
  sukat_sock_disconnect(client, server_from_client);
  sukat_sock_disconnect(server, server_endpoint);
  sukat_sock_destroy(client);
  sukat_sock_destroy(server);
}

class sukat_sock_test_sun_dgram : public ::testing::Test
{
protected:
  sukat_sock_test_sun_dgram() {
  }

  virtual ~sukat_sock_test_sun_dgram() {
  }

  virtual void SetUp() {
      memset(&default_cbs, 0, sizeof(default_cbs));
      memset(&default_params, 0, sizeof(default_params));
      memset(&default_endpoint_params, 0, sizeof(default_endpoint_params));
      memset(&tctx, 0, sizeof(tctx));

      get_random_socket(sun_template, sizeof(sun_template));
      default_cbs.log_cb = test_log_cb;
      default_cbs.msg_cb = msg_cb;
      default_params.caller_ctx = &tctx;

      default_endpoint_params.punix.name = sun_template;
      default_endpoint_params.domain = AF_UNIX;
      default_endpoint_params.punix.is_abstract = true;
      default_endpoint_params.type = SOCK_DGRAM;
      default_endpoint_params.server = true;

      server = sukat_sock_create(&default_params, &default_cbs);
      EXPECT_NE(nullptr, server);
      server_endpoint =
        sukat_sock_endpoint_add(server,&default_endpoint_params);
      EXPECT_NE(nullptr, server_endpoint);
  }

  virtual void TearDown() {
      default_endpoint_params.punix.name = NULL;
      sukat_sock_disconnect(server, server_endpoint);
      sukat_sock_destroy(server);
  }

  struct sukat_sock_cbs default_cbs;
  struct sukat_sock_params default_params;
  struct sukat_sock_endpoint_params default_endpoint_params;
  char sun_template[sizeof(((struct sockaddr_un *)0)->sun_path) - 2];
  sukat_sock_t *server;
  sukat_sock_endpoint_t *server_endpoint;
  struct read_ctx tctx;
};

TEST_F(sukat_sock_test_sun_dgram, sukat_sock_test_sun_dgram_recv)
{
  int fd;
  ssize_t ret;
  size_t i;
  const size_t n_messages = 9, message_size = 16;
  char buf[BUFSIZ];
  sukat_sock_endpoint_t client_endpoint;

  default_endpoint_params.server = false;
  fd = socket_create(NULL, &default_endpoint_params, &client_endpoint);
  EXPECT_GT(fd, -1);

  snprintf((char *)buf, sizeof(buf) - 1, "Hello there connectionless");
  ret = write(fd, buf, strlen(buf));
  EXPECT_EQ(strlen(buf), ret);

  tctx.buf = (uint8_t *)buf;
  tctx.compare_payload = true;
  tctx.msg_cb_should_visit = true;

  ret = sukat_sock_read(server, 0);
  EXPECT_EQ(0, ret);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  EXPECT_EQ(true, tctx.compared_payload);
  EXPECT_EQ(1, tctx.n_messages);
  tctx.msg_cb_visited = tctx.compared_payload = false;
  tctx.offset = 0;
  tctx.n_messages = 0;

  // Now test with many messages
  for (i = 0; i < n_messages; i++)
    {
      void *target = buf + i * message_size;

      memset(target, i, message_size);
      ret = write(fd, target, message_size);
      EXPECT_EQ(message_size, ret);
    }
  ret = sukat_sock_read(server, 0);
  EXPECT_EQ(0, ret);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  EXPECT_EQ(n_messages, tctx.n_messages);
  EXPECT_EQ(true, tctx.compared_payload);

  close(fd);
}

TEST_F(sukat_sock_test_sun_dgram, sukat_sock_test_sun_dgram_send)
{
  char buf[BUFSIZ];
  sukat_sock_t *server2;
  sukat_sock_endpoint_t *server2_endpoint, *server1_from_server2,
                        *server2_from_server1;
  enum sukat_sock_send_return sock_ret;
  int ret;

  tctx.buf = (uint8_t *)buf;
  tctx.compare_payload = true;

  server2 = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, server2);
  default_endpoint_params.server = false;

  server1_from_server2 =
    sukat_sock_endpoint_add(server2, &default_endpoint_params);
  ASSERT_NE(nullptr, server1_from_server2);

  get_random_socket(sun_template, sizeof(sun_template));
  default_endpoint_params.server = true;

  server2_endpoint = sukat_sock_endpoint_add(server2, &default_endpoint_params);
  ASSERT_NE(nullptr, server2_endpoint);

  snprintf(buf, sizeof(buf), "Hello there server 1");
  sock_ret = sukat_send_msg(server2, server1_from_server2,
                            (uint8_t *)buf, strlen(buf),
                            server2_endpoint);
  EXPECT_EQ(SUKAT_SEND_OK, sock_ret);

  tctx.copy_client = true;
  tctx.msg_cb_should_visit = true;
  ret = sukat_sock_read(server, 100);
  EXPECT_EQ(0, ret);
  ASSERT_EQ(true, tctx.msg_cb_visited);
  server2_from_server1 = tctx.newest_client;
  tctx.msg_cb_visited = tctx.copy_client = false;
  tctx.offset = 0;

  snprintf(buf, sizeof(buf), "Hey back from server1");
  sock_ret = sukat_send_msg(server, server2_from_server1, (uint8_t *)buf,
                            strlen(buf), server_endpoint);
  EXPECT_EQ(SUKAT_SEND_OK, sock_ret);

  ret = sukat_sock_read(server2, 100);
  EXPECT_EQ(0, ret);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  tctx.offset = 0;
  tctx.msg_cb_visited = false;

  // Send one without a source.
  snprintf(buf, sizeof(buf), "Hey from secret admirer");
  sock_ret = sukat_send_msg(server, server2_from_server1, (uint8_t *)buf,
                            strlen(buf), NULL);
  EXPECT_EQ(SUKAT_SEND_OK, sock_ret);

  ret = sukat_sock_read(server2, 100);
  EXPECT_EQ(0, ret);
  EXPECT_EQ(true, tctx.msg_cb_visited);

  sukat_sock_disconnect(server2, server2_endpoint);
  sukat_sock_disconnect(server2, server1_from_server2);
  sukat_sock_destroy(server2);
  free(server2_from_server1);
}

struct cb_disco_ctx
{
  sukat_sock_t *ctx;
  sukat_sock_endpoint_t *destroy_this_too;
  sukat_sock_endpoint_t *client;
  bool disco_in_len;
  bool disco_in_conn;
  bool disco_in_msg;
  bool destroy_in_len;
  bool destroy_in_conn;
  bool destroy_in_msg;
  int ret;
};

int len_cb_disconnects(void *ctx,
                       __attribute__((unused)) uint8_t *buf,
                       __attribute__((unused)) size_t buf_len)
{
  struct cb_disco_ctx *tctx = (struct cb_disco_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  if (tctx->disco_in_len)
    {
      EXPECT_NE(nullptr, tctx->client);
      sukat_sock_disconnect(tctx->ctx, tctx->client);
      tctx->client = NULL;
    }
  if (tctx->destroy_in_len)
    {
      if (tctx->destroy_this_too)
        {
          sukat_sock_disconnect(tctx->ctx, tctx->destroy_this_too);
        }
      tctx->destroy_this_too = NULL;
      sukat_sock_destroy(tctx->ctx);
    }
  return tctx->ret;
}

void *disco_conn_cb(void *ctx, sukat_sock_endpoint_t *client,
                    __attribute__((unused)) sukat_sock_event_t event)
{
  struct cb_disco_ctx *tctx = (struct cb_disco_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  tctx->client = client;
  if (tctx->disco_in_conn)
    {
      EXPECT_NE(nullptr, tctx->client);
      sukat_sock_disconnect(tctx->ctx, client);
      tctx->client = NULL;
    }
  if (tctx->destroy_in_conn)
    {
      if (tctx->destroy_this_too)
        {
          sukat_sock_disconnect(tctx->ctx, tctx->destroy_this_too);
        }
      tctx->destroy_this_too = NULL;
      sukat_sock_destroy(tctx->ctx);
    }
  tctx->client = client;
  return NULL;
}

void disco_msg_cb(void *ctx, sukat_sock_endpoint_t *client,
                  __attribute__((unused)) uint8_t *buf,
                  __attribute__((unused)) size_t buf_len)
{
  struct cb_disco_ctx *tctx = (struct cb_disco_ctx *)ctx;

  EXPECT_NE(nullptr, tctx);
  if (tctx->disco_in_msg)
    {
      EXPECT_NE(nullptr, tctx->client);
      sukat_sock_disconnect(tctx->ctx, client);
      tctx->client = NULL;
    }
  if (tctx->destroy_in_msg)
    {
      if (tctx->destroy_this_too)
        {
          sukat_sock_disconnect(tctx->ctx, tctx->destroy_this_too);
        }
      tctx->destroy_this_too = NULL;
      sukat_sock_destroy(tctx->ctx);
    }
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_removal_in_cb)
{
  sukat_sock_t *server, *client;
  sukat_sock_endpoint_t *server_endpoint, *client_endpoint;
  struct cb_disco_ctx tctx= { };
  int err;
  uint8_t msg[512];

  memset(msg, 0, sizeof(msg));
  default_cbs.conn_cb = disco_conn_cb;
  default_cbs.msg_cb = disco_msg_cb;
  default_cbs.msg_len_cb = len_cb_disconnects;
  default_endpoint_params.server = true;
  default_params.caller_ctx = &tctx;
  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);
  server_endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);
  tctx.ctx = server;

  default_endpoint_params.server = false;
  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);
  client_endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);

  // First disco in conn
  tctx.disco_in_conn = true;
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(1, server->n_connections);
  sukat_sock_disconnect(client, client_endpoint);

  // Disco in len_cb
  tctx.disco_in_conn = false;
  tctx.disco_in_len = true;

  client_endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(2, server->n_connections);

  err = sukat_send_msg(client, client_endpoint, msg, sizeof(msg), NULL);
  EXPECT_EQ(SUKAT_SEND_OK, err);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(1, server->n_connections);

  err = sukat_sock_read(client, 0);
  EXPECT_EQ(0, err);

  // Disco in msg_cb
  tctx.disco_in_len = false;
  tctx.disco_in_msg = true;

  client_endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(2, server->n_connections);

  err = sukat_send_msg(client, client_endpoint, msg, sizeof(msg), NULL);
  EXPECT_EQ(SUKAT_SEND_OK, err);

  tctx.ret = sizeof(msg);
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(1, server->n_connections);

  err = sukat_sock_read(client, 0);
  EXPECT_EQ(0, err);
  tctx.disco_in_msg = false;

  // same for destroys.
  tctx.ctx = server;

  client_endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);

  tctx.destroy_in_conn = tctx.disco_in_conn = true;
  tctx.destroy_this_too = server_endpoint;
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);

  sukat_sock_disconnect(client, client_endpoint);

  // Destroy in conn_cb
  get_random_socket(sun_template, sizeof(sun_template));
  tctx.destroy_in_conn = tctx.disco_in_conn = false;
  default_endpoint_params.server = true;
  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);
  server_endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);

  tctx.ctx = server;
  tctx.destroy_this_too = server_endpoint;
  default_endpoint_params.server = false;
  client_endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);

  // Destroy in len_cb
  tctx.disco_in_len = tctx.destroy_in_len = true;
  err = sukat_send_msg(client, client_endpoint, msg, sizeof(msg), NULL);
  EXPECT_EQ(SUKAT_SEND_OK, err);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);

  sukat_sock_disconnect(client, client_endpoint);
  tctx.disco_in_len = tctx.destroy_in_len = false;

  get_random_socket(sun_template, sizeof(sun_template));
  default_endpoint_params.server = true;
  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);
  server_endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);

  // Destroy in msg_cb.
  tctx.ctx = server;
  tctx.destroy_this_too = server_endpoint;
  default_endpoint_params.server = false;
  client_endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);

  tctx.disco_in_msg = tctx.destroy_in_msg = true;
  err = sukat_send_msg(client, client_endpoint, msg, sizeof(msg), NULL);
  EXPECT_EQ(SUKAT_SEND_OK, err);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);

  sukat_sock_disconnect(client, client_endpoint);
  sukat_sock_destroy(client);
  tctx.disco_in_msg = tctx.destroy_in_msg = false;
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_peering)
{
  sukat_sock_t *peer1, *peer2;
  sukat_sock_endpoint_t *endpoint1, *endpoint2;
  sukat_sock_endpoint_t *peer1_to_peer2, *peer2_to_peer1;
  sukat_sock_endpoint_t *peer1_from_peer2, *peer2_from_peer1;
  char *peer1_name, *peer2_name;
  struct read_ctx tctx = { };
  int err;
  uint8_t buf[BUFSIZ];
  struct test_msg *msg = (struct test_msg *)buf;
  enum sukat_sock_send_return send_ret;

  memset(buf, 0, sizeof(buf));
  default_cbs.msg_len_cb = len_cb;
  default_cbs.msg_cb = msg_cb;
  default_cbs.conn_cb = new_conn_cb_for_read;
  default_params.caller_ctx = (void *)&tctx;

  peer1 = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, peer1);
  peer2 = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, peer2);

  default_endpoint_params.server = true;
  endpoint1 = sukat_sock_endpoint_add(peer1, &default_endpoint_params);
  EXPECT_NE(nullptr, endpoint1);
  peer1_name = strdup(default_endpoint_params.punix.name);
  EXPECT_NE(nullptr, peer1_name);

  get_random_socket(sun_template, sizeof(sun_template));
  endpoint2 = sukat_sock_endpoint_add(peer2, &default_endpoint_params);
  EXPECT_NE(nullptr, endpoint2);
  peer2_name = strdup(default_endpoint_params.punix.name);
  EXPECT_NE(nullptr, peer2_name);

  default_endpoint_params.server = false;
  peer1_to_peer2 = sukat_sock_endpoint_add(peer1, &default_endpoint_params);
  EXPECT_NE(nullptr, peer1_to_peer2);
  default_endpoint_params.punix.name = peer1_name;
  peer2_to_peer1 = sukat_sock_endpoint_add(peer2, &default_endpoint_params);
  EXPECT_NE(nullptr, peer2_to_peer1);

  err = sukat_sock_read(peer1, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.connect_visited);
  peer2_from_peer1 = tctx.newest_client;

  tctx.connect_visited = false;
  err = sukat_sock_read(peer2, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.connect_visited);
  peer1_from_peer2 = tctx.newest_client;
  tctx.connect_visited = false;

  msg->len = 500;
  send_ret = sukat_send_msg(peer1, peer1_to_peer2, buf, msg->len, NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);
  send_ret = sukat_send_msg(peer2, peer2_to_peer1, buf, msg->len, NULL);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.msg_cb_should_visit = tctx.len_cb_should_visit = true;
  err = sukat_sock_read(peer1, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  tctx.msg_cb_visited = tctx.len_cb_visited = false;

  err = sukat_sock_read(peer2, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  tctx.msg_cb_visited = tctx.len_cb_visited = false;

  sukat_sock_disconnect(peer1, peer2_from_peer1);
  sukat_sock_disconnect(peer2, peer1_from_peer2);
  sukat_sock_disconnect(peer1, peer1_to_peer2);
  sukat_sock_disconnect(peer2, peer2_to_peer1);
  sukat_sock_disconnect(peer1, endpoint1);
  sukat_sock_disconnect(peer2, endpoint2);
  sukat_sock_destroy(peer1);
  sukat_sock_destroy(peer2);
  free(peer1_name);
  free(peer2_name);
}

class sukat_sock_test_inet : public ::testing::Test
{
protected:
  // You can remove any or all of the following functions if its body is empty.

  sukat_sock_test_inet() {
      // You can do set-up work for each test here.
  }

  virtual ~sukat_sock_test_inet() {
      // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up and
  // cleaning up each test, you can define the following methods:
  virtual void SetUp() {
      memset(&default_cbs, 0, sizeof(default_cbs));
      memset(&default_params, 0, sizeof(default_params));
      memset(&default_endpoint_params, 0, sizeof(default_endpoint_params));

      default_cbs.log_cb = test_log_cb;

      default_endpoint_params.pinet.ip = local_ipv4;
      default_endpoint_params.domain = AF_UNSPEC;
      default_endpoint_params.type = SOCK_STREAM;
  }

  virtual void TearDown() {
      // Code here will be called immediately after each test (right
      // before the destructor).
  }

  // Objects declared here can be used by all tests
  struct sukat_sock_cbs default_cbs;
  struct sukat_sock_params default_params;
  struct sukat_sock_endpoint_params default_endpoint_params;
  const char *local_ipv4 = "127.0.0.1", *local_ipv6 = "::1";
};

void *inet_conn_cb(void *ctx, sukat_sock_endpoint_t *client,
                   sukat_sock_event_t event)
{
  struct read_ctx *tctx = (struct read_ctx *)ctx;
  tctx->connect_visited = true;
  tctx->newest_client = client;
  if (tctx->should_disconnect)
    {
      EXPECT_EQ(SUKAT_SOCK_CONN_EVENT_DISCONNECT, event);
    }
  return NULL;
}

TEST_F(sukat_sock_test_inet, sukat_sock_test_basic_client_server)
{
  sukat_sock_t *ctx, *client_ctx;;
  sukat_sock_endpoint_t *server_endpoint, *client_endpoint;
  char portbuf[strlen("65535") + 1];
  int err;
  struct read_ctx tctx = { };
  sukat_sock_endpoint_t *client = NULL;
  uint8_t buf[BUFSIZ];
  struct test_msg *msg = (struct test_msg*)buf;
  enum sukat_sock_send_return ret;
  size_t messages_sent = 0;
  tctx.buf = buf;

  memset(buf, 0, sizeof(buf));

  default_endpoint_params.server = true;
  default_params.caller_ctx = &tctx;
  default_cbs.conn_cb = inet_conn_cb;
  default_cbs.msg_cb = msg_cb;
  default_cbs.msg_len_cb = len_cb;
  ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);
  server_endpoint = sukat_sock_endpoint_add(ctx, &default_endpoint_params);
  EXPECT_NE(nullptr, server_endpoint);
  EXPECT_EQ(AF_INET, get_domain(server_endpoint));
  EXPECT_EQ(SOCK_STREAM, server_endpoint->info.type);

  EXPECT_NE(0, sukat_sock_get_port(server_endpoint));
  snprintf(portbuf, sizeof(portbuf), "%hu",
           sukat_sock_get_port(server_endpoint));
  default_endpoint_params.server = false;
  default_endpoint_params.pinet.port = portbuf;

  client_ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client_ctx);
  client_endpoint =
    sukat_sock_endpoint_add(client_ctx, &default_endpoint_params);
  EXPECT_NE(nullptr, client_endpoint);
  EXPECT_EQ(AF_INET, get_domain(client_endpoint));
  EXPECT_EQ(SOCK_STREAM, client_endpoint->info.type);

  err = sukat_sock_read(ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.connect_visited);
  client = tctx.newest_client;

  tctx.connect_visited = false;
  err = sukat_sock_read(client_ctx, 100);
  EXPECT_EQ(0, err);
  EXPECT_NE(true, client_endpoint->connect_in_progress);
  EXPECT_NE(true, client_endpoint->epollout);
  EXPECT_EQ(true, tctx.connect_visited);
  tctx.connect_visited = false;

  tctx.msg_cb_should_visit = true;
  /* Lets try to get partial writes/reads */
  msg->type = 0;
  msg->len = 5555;
  while ((ret = sukat_send_msg(ctx, client, buf, msg->len, NULL)) ==
         SUKAT_SEND_OK)
    {
      messages_sent++;
    }
  EXPECT_NE(0, client->write_cache.len);
  EXPECT_EQ(true, client->epollout);

  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(tctx.n_messages, messages_sent - 1);

  err = sukat_sock_read(ctx, 0);
  EXPECT_EQ(0, err);

  tctx.compare_payload = true;
  err = sukat_sock_read(client_ctx, 100);
  EXPECT_EQ(0, err);
  EXPECT_EQ(tctx.n_messages, messages_sent);

  tctx.should_disconnect = true;
  sukat_sock_disconnect(ctx, client);
  err = sukat_sock_read(client_ctx, 100);
  EXPECT_EQ(0, err);

  sukat_sock_destroy(client_ctx);
  sukat_sock_disconnect(ctx, server_endpoint);
  sukat_sock_destroy(ctx);
}

TEST_F(sukat_sock_test_inet, sukat_sock_test_ipv6)
{
  sukat_sock_t *server, *client;
  sukat_sock_endpoint_t *server_endpoint, *client_endpoint;
  char portbuf[strlen("65535") + 1];
  int err;

  default_endpoint_params.server = true;
  default_endpoint_params.pinet.ip = local_ipv6;
  default_endpoint_params.type = SOCK_DGRAM;

  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);
  server_endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
  EXPECT_EQ(AF_INET6, get_domain(server_endpoint));
  EXPECT_EQ(SOCK_DGRAM, server_endpoint->info.type);

  EXPECT_NE(0, server_endpoint->info.sin.sin_port);
  snprintf(portbuf, sizeof(portbuf), "%hu",
           ntohs(server_endpoint->info.sin6.sin6_port));
  default_endpoint_params.server = false;
  default_endpoint_params.pinet.port = portbuf;

  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);
  client_endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_EQ(AF_INET6, get_domain(client_endpoint));
  EXPECT_EQ(SOCK_DGRAM, client_endpoint->info.type);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);

  sukat_sock_disconnect(client, client_endpoint);
  sukat_sock_destroy(client);
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  sukat_sock_disconnect(server, server_endpoint);
  sukat_sock_destroy(server);
}

class sukat_sock_test_inet_stream_server : public ::testing::Test
{
protected:

  sukat_sock_test_inet_stream_server() {
  }

  virtual ~sukat_sock_test_inet_stream_server() {
  }

  virtual void SetUp() {
      memset(&default_cbs, 0, sizeof(default_cbs));
      memset(&default_params, 0, sizeof(default_params));
      memset(&default_endpoint_params, 0, sizeof(default_endpoint_params));

      default_cbs.log_cb = test_log_cb;

      default_endpoint_params.domain = AF_UNSPEC;
      default_endpoint_params.type = SOCK_STREAM;
      default_endpoint_params.server = true;
      default_endpoint_params.pinet.port = portbuf;
      snprintf(portbuf, sizeof(portbuf), "%hu", (unsigned short)0);

      server = sukat_sock_create(&default_params, &default_cbs);
      EXPECT_NE(nullptr, server);
      endpoint = sukat_sock_endpoint_add(server, &default_endpoint_params);
      EXPECT_NE(nullptr, endpoint);

      EXPECT_NE(0, sukat_sock_get_port(endpoint));
      snprintf(portbuf, sizeof(portbuf), "%hu",
               sukat_sock_get_port(endpoint));
      default_endpoint_params.server = false;
  }

  virtual void TearDown() {
      sukat_sock_disconnect(server, endpoint);
      sukat_sock_destroy(server);
  }

  struct sukat_sock_cbs default_cbs;
  struct sukat_sock_params default_params;
  struct sukat_sock_endpoint_params default_endpoint_params;
  sukat_sock_t *server;
  sukat_sock_endpoint_t *endpoint;
  char portbuf[strlen("65535") + 1];
};

struct failed_conn_ctx
{
  sukat_sock_endpoint_t *endpoint;
  unsigned int should_visit:1;
  unsigned int visited:1;
  unsigned int unused:6;
};

void *failed_conn_cb(void *caller_ctx, sukat_sock_endpoint_t *endpoint,
                     enum sukat_sock_new_conn_event event)
{
  EXPECT_NE(nullptr, caller_ctx);
  if (caller_ctx)
    {
      struct failed_conn_ctx *conn_ctx = (struct failed_conn_ctx *)caller_ctx;

      EXPECT_EQ(true, conn_ctx->should_visit);
      EXPECT_EQ(SUKAT_SOCK_CONN_EVENT_DISCONNECT, event);
      EXPECT_EQ(conn_ctx->endpoint, endpoint);
      conn_ctx->endpoint = NULL;
      conn_ctx->visited = true;
    }
  return NULL;
}

TEST_F(sukat_sock_test_inet_stream_server, sukat_sock_test_failed_conn)
{
  sukat_sock_t *client;
  struct failed_conn_ctx conn_ctx = { };
  int err;

  default_params.caller_ctx = &conn_ctx;
  default_cbs.conn_cb = failed_conn_cb;

  client = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, client);
  conn_ctx.endpoint = sukat_sock_endpoint_add(client, &default_endpoint_params);
  EXPECT_NE(nullptr, conn_ctx.endpoint);

  sukat_sock_disconnect(server, endpoint);
  endpoint = NULL;
  conn_ctx.should_visit = true;
  err = sukat_sock_read(client, 100);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, conn_ctx.visited);
  EXPECT_EQ(nullptr, conn_ctx.endpoint);

  sukat_sock_destroy(client);
}

class sukat_sock_test_unix_splice : public ::testing::Test
{
protected:

  struct splice_ctx
    {
      int intermediary_fds[2];
      int server_pair[2];
      int client_pair[2];
      sukat_sock_endpoint_t *client_from_server;
    };

  sukat_sock_test_unix_splice() {
  }

  virtual ~sukat_sock_test_unix_splice() {
  }

  static void *splice_conn_cb(void *ctx, sukat_sock_endpoint_t *endpoint,
                              sukat_sock_event_t event)
    {
      struct splice_ctx *test_ctx = (struct splice_ctx *)ctx;

      EXPECT_NE(nullptr, test_ctx);
      if (event == SUKAT_SOCK_CONN_EVENT_ACCEPTED)
        {
          test_ctx->client_from_server = endpoint;
        }
      else if (event == SUKAT_SOCK_CONN_EVENT_DISCONNECT)
        {
          if (endpoint == test_ctx->client_from_server)
            {
              test_ctx->client_from_server = NULL;
            }
        }
      return NULL;
    }

  static void
    splice_splice_cb(void *ctx, sukat_sock_endpoint_t *endpoint,
                     int *fd, int **intermediary)
    {
      struct splice_ctx *test_ctx = (struct splice_ctx *)ctx;

      EXPECT_NE(nullptr, test_ctx);
      if (endpoint == test_ctx->client_from_server)
        {
          *fd = test_ctx->server_pair[1];
        }
      else
        {
          *fd = test_ctx->client_pair[1];
        }
      /* Use same fds for server and client intermediary. Yeah that'll probably
       * never misfire.. */
      if (test_ctx->intermediary_fds[0] != -1 &&
          test_ctx->intermediary_fds[1] != -1)
        {
          *intermediary = test_ctx->intermediary_fds;
        }
    }

  virtual void SetUp() {
      struct sukat_sock_params params = { };
      struct sukat_sock_cbs cbs = { };
      struct sukat_sock_endpoint_params eparams = { };
      unsigned int i;
      char abstract_socket[256];
      int err, *intptr;

      for (intptr = (int *)&test_ctx, i = 0; i < n_fds; i++, intptr++)
        {
          *intptr = -1;
        }

      params.caller_ctx = &test_ctx;
      cbs.log_cb = test_log_cb;
      cbs.conn_cb = splice_conn_cb;
      cbs.splice_cb = splice_splice_cb;
      server = sukat_sock_create(&params, &cbs);
      EXPECT_NE(nullptr, server);
      client = sukat_sock_create(&params, &cbs);
      EXPECT_NE(nullptr, client);

      get_random_socket(abstract_socket, sizeof(abstract_socket));
      eparams.type = SOCK_STREAM;
      eparams.domain = AF_UNIX;
      eparams.punix.is_abstract = true;
      eparams.punix.name = abstract_socket;
      eparams.server = true;

      server_endpoint = sukat_sock_endpoint_add(server, &eparams);
      EXPECT_NE(nullptr, server_endpoint);
      eparams.server = false;
      client_endpoint = sukat_sock_endpoint_add(client, &eparams);
      EXPECT_NE(nullptr, client_endpoint);

      err = sukat_sock_read(server, 100);
      EXPECT_EQ(0, err);
      EXPECT_NE(nullptr, test_ctx.client_from_server);

      err = socketpair(AF_UNIX, SOCK_STREAM | O_NONBLOCK | O_CLOEXEC,
                       0, test_ctx.client_pair);
      EXPECT_EQ(0, err);
      err = socketpair(AF_UNIX, SOCK_STREAM | O_NONBLOCK | O_CLOEXEC,
                       0, test_ctx.server_pair);
      EXPECT_EQ(0, err);
  }

  virtual void TearDown()
    {
      unsigned int i;
      int *fdptr = (int *)&test_ctx;

      for (i = 0; i < n_fds; i++, fdptr++)
        {
          if (*fdptr != -1)
            {
              close(*fdptr);
            }
        }
      sukat_sock_disconnect(client, test_ctx.client_from_server);
      sukat_sock_disconnect(client, client_endpoint);
      sukat_sock_disconnect(server, server_endpoint);
      sukat_sock_destroy(client);
      sukat_sock_destroy(server);
    }

  struct splice_ctx test_ctx;
  sukat_sock_t *server, *client;
  sukat_sock_endpoint_t *server_endpoint, *client_endpoint;
  const size_t n_fds = 6;
};

TEST_F(sukat_sock_test_unix_splice, sukat_sock_test_splice_basic)
{
  int err;
  ssize_t ret;
  char buf[BUFSIZ], cmpbuf[BUFSIZ];

  err = pipe2(test_ctx.intermediary_fds, O_CLOEXEC | O_NONBLOCK);
  EXPECT_EQ(0, err);

  snprintf(buf, sizeof(buf), "Hello from client");
  ret = write(test_ctx.client_pair[0], buf, strlen(buf));
  EXPECT_LT(0, ret);

  ret = sukat_sock_splice_to(client, client_endpoint, test_ctx.client_pair[1],
                             test_ctx.intermediary_fds);
  EXPECT_EQ(strlen(buf), ret);

  err = sukat_sock_read(server, 100);
  EXPECT_EQ(0, err);

  ret = read(test_ctx.server_pair[0], cmpbuf, sizeof(cmpbuf));
  EXPECT_EQ(strlen(buf), ret);
  err = strncmp(buf, cmpbuf, strlen(buf));
  EXPECT_EQ(0, err);
}

TEST_F(sukat_sock_test_unix_splice, sukat_sock_test_splice_bufsiz)
{
  int err;
  ssize_t ret;
  size_t total = 0, total_recv = 0;
  char buf[BUFSIZ], cmpbuf[BUFSIZ];

  err = pipe2(test_ctx.intermediary_fds, O_CLOEXEC | O_NONBLOCK);
  EXPECT_EQ(0, err);

  memset(buf, 'c', sizeof(buf));
  memset(cmpbuf, 0, sizeof(cmpbuf));

  while (total < sizeof(buf))
    {
      ret = write(test_ctx.server_pair[0], buf + total,  sizeof(buf) - total);
      EXPECT_LT(0, ret);
      total += (size_t)ret;
      ret = sukat_sock_splice_to(server, test_ctx.client_from_server,
                                 test_ctx.server_pair[1],
                                 test_ctx.intermediary_fds);
      EXPECT_LT(0, ret);
      err = sukat_sock_read(client, 100);
      EXPECT_EQ(0, err);
      ret = read(test_ctx.client_pair[0], cmpbuf + total_recv,
                 sizeof(cmpbuf) - total_recv);
      EXPECT_LT(0, ret);
    }
  err = memcmp(buf, cmpbuf, sizeof(buf));
  EXPECT_EQ(0, err);
}

TEST_F(sukat_sock_test_unix_splice, sukat_sock_test_splice_pipes)
{
  int *fdptr;
  unsigned int i;
  int err;
  ssize_t ret;
  char buf[BUFSIZ], cmpbuf[BUFSIZ];

  for (i = 0, fdptr = (int *)&test_ctx.server_pair; i < 4; i++, fdptr++)
    {
      close(*fdptr);
      *fdptr = -1;
    }
  err = pipe2(test_ctx.server_pair, O_CLOEXEC | O_NONBLOCK);
  EXPECT_EQ(0, err);
  err = pipe2(test_ctx.client_pair, O_CLOEXEC | O_NONBLOCK);
  EXPECT_EQ(0, err);

  snprintf(buf, sizeof(buf), "Client tries to do this without intermediary");
  ret = write(test_ctx.client_pair[1], buf, strlen(buf));
  EXPECT_EQ(strlen(buf), ret);

  ret = sukat_sock_splice_to(client, client_endpoint, test_ctx.client_pair[0],
                             NULL);
  EXPECT_LE(0, ret);
  err = sukat_sock_read(server, 100);
  EXPECT_EQ(0, err);
  ret = read(test_ctx.server_pair[0], cmpbuf, sizeof(buf));
  EXPECT_EQ(strlen(buf), ret);
  err = memcmp(buf, cmpbuf, strlen(buf));
  EXPECT_EQ(0, err);
}
