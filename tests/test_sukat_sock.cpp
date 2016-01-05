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
      default_cbs.log_cb = test_log_cb;
      memset(&default_params, 0, sizeof(default_params));
      // Code here will be called immediately after the constructor (right
      // before each test).
  }

  virtual void TearDown() {
      // Code here will be called immediately after each test (right
      // before the destructor).
  }
  void get_random_port(struct sukat_sock_params *params)
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
};



struct test_ctx
{
  int yeah;
};

TEST_F(sukat_sock_test_tipc, sukat_sock_test_tipc)
{
  sukat_sock_t *ctx, *client_ctx;
  struct test_ctx tctx = { };
  bool bret;
  int err;

  default_params.caller_ctx = &tctx;
  default_params.server = true;
  default_params.domain = AF_TIPC;
  default_params.type = SOCK_SEQPACKET;

  get_random_port(&default_params);

  if (check_tipc() == false)
    {
      default_cbs.log_cb(SUKAT_LOG,
                         "Skipping TIPC socket. modprobe tipc to enable");
      return;
    }

  ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);

  default_params.server = false;
  bret = wait_for_tipc_server(ctx, default_params.ptipc.port_type,
                              default_params.ptipc.port_instance, 1000);
  EXPECT_EQ(true, bret);

  client_ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client_ctx);

  err = sukat_sock_read(ctx, 0);
  EXPECT_NE(-1, err);

  sukat_sock_destroy(client_ctx);
  err = sukat_sock_read(ctx, 0);
  EXPECT_NE(-1, err);

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

      default_cbs.log_cb = test_log_cb;

      get_random_socket();
      default_params.punix.name = sun_template;
      default_params.domain = AF_UNIX;
      default_params.punix.is_abstract = true;
      default_params.type = SOCK_STREAM;
  }

  virtual void TearDown() {
      default_params.punix.name = NULL;
      // Code here will be called immediately after each test (right
      // before the destructor).
  }

  void get_random_socket()
    {
      int fd;
      snprintf(sun_template, sizeof(sun_template),
               "/tmp/sukat_sock_sun_test_XXXXXX");

      fd = mkstemp(sun_template);
      ASSERT_NE(-1, fd);
      close(fd);
      unlink(sun_template);
    }
  // Objects declared here can be used by all tests
  struct sukat_sock_cbs default_cbs;
  struct sukat_sock_params default_params;
  char sun_template[sizeof(((struct sockaddr_un *)0)->sun_path) - 2];
};

struct sun_test_ctx
{
  bool connected_should;
  bool connected_visited;
  bool connected_should_disconnect;
  sukat_sock_client_t *newest_client;
  void *new_ctx;
  size_t n_connects;
  size_t n_disconnects;
};

struct test_client
{
  int id;
};

void *new_conn_cb(void *ctx, sukat_sock_client_t *client,
                  struct sockaddr_storage *sockaddr,
                  size_t sock_len, bool disconnect)
{
  struct sun_test_ctx *tctx = (struct sun_test_ctx *)ctx;

  EXPECT_EQ(true, tctx->connected_should);
  if (disconnect)
    {
      EXPECT_EQ(true, tctx->connected_should_disconnect);
      tctx->n_disconnects++;
    }
  else
    {
      tctx->n_connects++;
    }
  tctx->newest_client = client;
  (void)sockaddr;
  (void)sock_len;
  tctx->connected_visited = true;
  return tctx->new_ctx;
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_stream_connect)
{
  sukat_sock_t *ctx, *client_ctx;
  struct sun_test_ctx tctx = { };
  int err, master_epoll;

  // Test with no params
  ctx = sukat_sock_create(NULL, &default_cbs);
  EXPECT_EQ(nullptr, ctx);

  // Test with another epoll.
  master_epoll = epoll_create1(EPOLL_CLOEXEC);
  EXPECT_NE(-1, master_epoll);

  // First with a faulty master_epoll.
  default_params.server = true;
  default_params.master_epoll_fd_set = true;
  default_params.master_epoll_fd = -1;
  ctx = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_EQ(nullptr, ctx);
  get_random_socket();

  default_params.master_epoll_fd = master_epoll;
  ctx = sukat_sock_create(&default_params, &default_cbs);
  EXPECT_NE(nullptr, ctx);
  sukat_sock_destroy(ctx);
  close(master_epoll);
  default_params.master_epoll_fd_set = false;

  get_random_socket();

  default_params.caller_ctx = &tctx;
  default_cbs.conn_cb = new_conn_cb;

  ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);

  default_params.server = false;
  default_cbs.conn_cb = NULL;
  client_ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);

  tctx.connected_should = true;
  err = sukat_sock_read(ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.connected_visited);
  EXPECT_EQ(2, ctx->n_connections);
  tctx.connected_should = tctx.connected_visited = false;

  sukat_sock_destroy(client_ctx);

  tctx.connected_should = tctx.connected_should_disconnect = true;
  err = sukat_sock_read(ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.connected_visited);
  tctx.connected_should = tctx.connected_visited =
    tctx.connected_should_disconnect = false;

    {
      size_t i;
      const size_t n_clients = SOMAXCONN;
      sukat_sock_t *clients[n_clients];
      tctx.n_connects = tctx.n_disconnects = 0;

      for (i = 0; i < n_clients; i++)
        {
          clients[i] = sukat_sock_create(&default_params, &default_cbs);
          EXPECT_NE(nullptr, clients[i]);
        }
      tctx.connected_should = true;
      err = sukat_sock_read(ctx, 0);
      EXPECT_NE(-1, err);
      EXPECT_EQ(true, tctx.connected_visited);
      EXPECT_EQ(n_clients + 1, ctx->n_connections);
      EXPECT_EQ(n_clients, tctx.n_connects);
      tctx.connected_should = tctx.connected_visited = false;

      for (i = 0; i < n_clients; i++)
        {
          sukat_sock_destroy(clients[i]);
        }
      tctx.connected_should = tctx.connected_should_disconnect = true;
      err = sukat_sock_read(ctx, 0);
      EXPECT_NE(-1, err);
      EXPECT_EQ(true, tctx.connected_visited);
      EXPECT_EQ(n_clients, tctx.n_disconnects);
    }
  sukat_sock_destroy(ctx);
}

struct read_ctx
{
  bool len_cb_should_visit;
  bool len_cb_visited;
  bool return_corrupt;
  sukat_sock_client_t *newest_client;
  bool should_disconnect;
  bool connect_visited;
  bool msg_cb_should_visit;
  bool msg_cb_visited;
  bool compare_payload;
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

static void msg_cb(void *ctx, sukat_sock_client_t *client, uint8_t *buf,
                   size_t buf_len)
{
  struct read_ctx *tctx = (struct read_ctx*)ctx;

  tctx->msg_cb_visited = true;
  tctx->newest_client = client;
  if (tctx->compare_payload)
    {
      int compareval;

      compareval = memcmp(buf, tctx->buf + tctx->offset, buf_len);
      EXPECT_EQ(0, compareval);
      tctx->offset += buf_len;
    }
  tctx->n_messages++;
}

void *new_conn_cb_for_read(void *ctx, sukat_sock_client_t *client,
  __attribute__((unused))struct sockaddr_storage *sockaddr,
  __attribute__((unused))size_t sock_len, bool disconnect)
{
  struct read_ctx *tctx = (struct read_ctx *)ctx;
  tctx->newest_client = client;
  EXPECT_EQ(tctx->should_disconnect, disconnect);
  tctx->connect_visited = true;
  return NULL;
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_stream_read)
{
  sukat_sock_t *ctx, *client_ctx;
  sukat_sock_client_t *client;
  uint8_t buf[BUFSIZ];
  struct test_msg *msg = (struct test_msg *)buf;
  struct read_ctx tctx = { };
  int err;
  enum sukat_sock_send_return send_ret;
  size_t msg_len = 5000, i, total_sent, total_read;

  default_cbs.msg_len_cb = len_cb;
  default_cbs.conn_cb = new_conn_cb_for_read;
  default_cbs.msg_cb = msg_cb;
  default_params.server = true;
  default_params.caller_ctx = (void *)&tctx;
  tctx.buf = buf;
  tctx.compare_payload = true;

  ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);

  default_params.server = false;
  client_ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client_ctx);

  err = sukat_sock_read(ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(2, ctx->n_connections);
  client = tctx.newest_client;

  /* Simple single message */
  msg->type = 0;
  msg->len = sizeof(*msg);

  send_ret = sukat_send_msg(client_ctx, NULL, buf, msg->len);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.len_cb_should_visit = tctx.msg_cb_should_visit = true;
  err = sukat_sock_read(ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(true, tctx.msg_cb_visited);
  tctx.offset = 0;

  /* Reply */
  err = sukat_send_msg(ctx, client, buf, msg->len);
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

  send_ret = sukat_send_msg(ctx, client, buf, sizeof(*msg) / 2);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(false, tctx.msg_cb_visited);
  tctx.offset = 0;

  /* Continue */
  send_ret = sukat_send_msg(ctx, client, buf + (sizeof(*msg) / 2),
                            sizeof(*msg) / 2);
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
  send_ret = sukat_send_msg(ctx, client, buf, msg_len / 2);
  EXPECT_EQ(SUKAT_SEND_OK, send_ret);

  tctx.msg_cb_should_visit = false;
  err = sukat_sock_read(client_ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.len_cb_visited);
  EXPECT_EQ(false, tctx.msg_cb_visited);
  tctx.len_cb_visited = tctx.msg_cb_visited = false;
  tctx.offset = 0;

  /* Send second half */
  send_ret = sukat_send_msg(ctx, client, buf + (msg_len / 2), msg_len / 2);
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
      send_ret = sukat_send_msg(ctx, client, (uint8_t *)msg, msg->len);
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
  while ((send_ret = sukat_send_msg(ctx, client,
                                    (uint8_t *)msg, msg->len)) == SUKAT_SEND_OK)
    {
      total_sent += msg_len;
    }
  EXPECT_EQ(SUKAT_SEND_EAGAIN, send_ret);
  EXPECT_GT(total_sent, 0);

  total_read = 0;
  while ((err = read(client_ctx->fd, buf, sizeof(buf))) > 0)
    {
      total_read += err;
    }
  EXPECT_TRUE(err == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
  EXPECT_GT(total_read, 0);

  /* So somehow I can't get the send side to ever send a partial message
   * I'll just do the send caching test in AF_INET */

  sukat_sock_disconnect(ctx, client);
  sukat_sock_destroy(client_ctx);
  sukat_sock_destroy(ctx);
}

struct cb_disco_ctx
{
  sukat_sock_t *ctx;
  sukat_sock_client_t *client;
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
      sukat_sock_destroy(tctx->ctx);
    }
  return tctx->ret;
}

void *disco_conn_cb(void *ctx, sukat_sock_client_t *client,
                    __attribute__((unused)) struct sockaddr_storage *saddr,
                    __attribute__((unused)) size_t sock_len,
                    __attribute__((unused)) bool disconnect)
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
      sukat_sock_destroy(tctx->ctx);
    }
  tctx->client = client;
  return NULL;
}

void disco_msg_cb(void *ctx, sukat_sock_client_t *client,
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
      sukat_sock_destroy(tctx->ctx);
    }
}

TEST_F(sukat_sock_test_sun, sukat_sock_test_sun_removal_in_cb)
{
  sukat_sock_t *server, *client;
  struct cb_disco_ctx tctx= { };
  int err;
  uint8_t msg[512];

  memset(msg, 0, sizeof(msg));
  default_cbs.conn_cb = disco_conn_cb;
  default_cbs.msg_cb = disco_msg_cb;
  default_cbs.msg_len_cb = len_cb_disconnects;
  default_params.server = true;
  default_params.caller_ctx = &tctx;
  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);
  tctx.ctx = server;

  default_params.server = false;
  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);

  // First disco in conn
  tctx.disco_in_conn = true;
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(1, server->n_connections);
  sukat_sock_destroy(client);

  // Disco in len_cb
  tctx.disco_in_conn = false;
  tctx.disco_in_len = true;

  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(2, server->n_connections);

  err = sukat_send_msg(client, NULL, msg, sizeof(msg));
  EXPECT_EQ(SUKAT_SEND_OK, err);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(1, server->n_connections);

  err = sukat_sock_read(client, 0);
  EXPECT_EQ(ERR_FATAL, err);
  sukat_sock_destroy(client);

  // Disco in msg_cb
  tctx.disco_in_len = false;
  tctx.disco_in_msg = true;

  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(2, server->n_connections);

  err = sukat_send_msg(client, NULL, msg, sizeof(msg));
  EXPECT_EQ(SUKAT_SEND_OK, err);

  tctx.ret = sizeof(msg);
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(1, server->n_connections);

  err = sukat_sock_read(client, 0);
  EXPECT_EQ(ERR_FATAL, err);
  sukat_sock_destroy(client);
  tctx.disco_in_msg = false;

  // same for destroys.
  tctx.ctx = server;

  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);

  tctx.destroy_in_conn = tctx.disco_in_conn = true;
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);

  sukat_sock_destroy(client);

  // Destroy in conn_cb
  get_random_socket();
  tctx.destroy_in_conn = tctx.disco_in_conn = false;
  default_params.server = true;
  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);

  tctx.ctx = server;
  default_params.server = false;
  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);

  // Destroy in len_cb
  tctx.disco_in_len = tctx.destroy_in_len = true;
  err = sukat_send_msg(client, NULL, msg, sizeof(msg));
  EXPECT_EQ(SUKAT_SEND_OK, err);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);

  sukat_sock_destroy(client);
  tctx.disco_in_len = tctx.destroy_in_len = false;

  get_random_socket();
  default_params.server = true;
  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);

  // Destroy in msg_cb.
  tctx.ctx = server;
  default_params.server = false;
  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);

  tctx.disco_in_msg = tctx.destroy_in_msg = true;
  err = sukat_send_msg(client, NULL, msg, sizeof(msg));
  EXPECT_EQ(SUKAT_SEND_OK, err);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);

  sukat_sock_destroy(client);
  tctx.disco_in_msg = tctx.destroy_in_msg = false;
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

      default_cbs.log_cb = test_log_cb;

      default_params.pinet.ip = local_ipv4;
      default_params.domain = AF_UNSPEC;
      default_params.type = SOCK_STREAM;
  }

  virtual void TearDown() {
      // Code here will be called immediately after each test (right
      // before the destructor).
  }

  // Objects declared here can be used by all tests
  struct sukat_sock_cbs default_cbs;
  struct sukat_sock_params default_params;
  const char *local_ipv4 = "127.0.0.1", *local_ipv6 = "::1";
};

void *inet_conn_cb(void *ctx, sukat_sock_client_t *client,
                   struct sockaddr_storage *saddr, size_t slen,
                   bool disconnect)
{
  struct read_ctx *tctx = (struct read_ctx *)ctx;
  tctx->connect_visited = true;
  tctx->newest_client = client;
  (void)saddr;
  (void)slen;
  EXPECT_EQ(tctx->should_disconnect, disconnect);
  return NULL;
}

TEST_F(sukat_sock_test_inet, sukat_sock_test_basic_client_server)
{
  sukat_sock_t *ctx, *client_ctx;;
  char portbuf[strlen("65535") + 1];
  int err;
  struct read_ctx tctx = { };
  sukat_sock_client_t *client = NULL;
  uint8_t buf[BUFSIZ];
  struct test_msg *msg = (struct test_msg*)buf;
  enum sukat_sock_send_return ret;
  size_t messages_sent = 0;
  tctx.buf = buf;

  memset(buf, 0, sizeof(buf));

  default_params.server = true;
  default_params.caller_ctx = &tctx;
  default_cbs.conn_cb = inet_conn_cb;
  default_cbs.msg_cb = msg_cb;
  default_cbs.msg_len_cb = len_cb;
  ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, ctx);
  EXPECT_EQ(AF_INET, ctx->domain);
  EXPECT_EQ(SOCK_STREAM, ctx->type);

  EXPECT_NE(0, ctx->sin.sin_port);
  snprintf(portbuf, sizeof(portbuf), "%hu", ntohs(ctx->sin.sin_port));
  default_params.server = false;
  default_params.pinet.port = portbuf;

  client_ctx = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client_ctx);
  EXPECT_EQ(AF_INET, client_ctx->domain);
  EXPECT_EQ(SOCK_STREAM, client_ctx->type);

  err = sukat_sock_read(ctx, 0);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, tctx.connect_visited);
  client = tctx.newest_client;

  tctx.connect_visited = false;
  err = sukat_sock_read(client_ctx, 100);
  EXPECT_EQ(0, err);
  EXPECT_NE(true, client_ctx->connect_in_progress);
  EXPECT_NE(true, client_ctx->epollout);
  EXPECT_EQ(true, tctx.connect_visited);
  tctx.connect_visited = false;

  /* Lets try to get partial writes/reads */
  msg->type = 0;
  msg->len = 5555;
  while ((ret = sukat_send_msg(ctx, client, buf, msg->len)) == SUKAT_SEND_OK)
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

  sukat_sock_disconnect(ctx, client);
  err = sukat_sock_read(client_ctx, 100);
  EXPECT_EQ(-1, err);

  sukat_sock_destroy(client_ctx);
  sukat_sock_destroy(ctx);
}

TEST_F(sukat_sock_test_inet, sukat_sock_test_ipv6)
{
  sukat_sock_t *server, *client;
  char portbuf[strlen("65535") + 1];
  int err;

  default_params.server = true;
  default_params.pinet.ip = local_ipv6;
  default_params.type = SOCK_DGRAM;

  server = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, server);
  EXPECT_EQ(AF_INET6, server->domain);
  EXPECT_EQ(SOCK_DGRAM, server->type);

  EXPECT_NE(0, server->sin.sin_port);
  snprintf(portbuf, sizeof(portbuf), "%hu", ntohs(server->sin6.sin6_port));
  default_params.server = false;
  default_params.pinet.port = portbuf;

  client = sukat_sock_create(&default_params, &default_cbs);
  ASSERT_NE(nullptr, client);
  EXPECT_EQ(AF_INET6, client->domain);
  EXPECT_EQ(SOCK_DGRAM, client->type);

  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);

  sukat_sock_destroy(client);
  err = sukat_sock_read(server, 0);
  EXPECT_EQ(0, err);
  sukat_sock_destroy(server);
}
