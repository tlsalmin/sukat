#include <iostream>
#include <cstdio>
#include <cstring>
#include <memory>
#include <list>
#include <benchmark/benchmark.h>

extern "C" {
#include "sukat_sock.h"
#include "unistd.h"
}

static void domain_type_args(benchmark::internal::Benchmark *b)
{
  //std::list<int> domains = {AF_UNIX, AF_INET, AF_INET6};
  std::list<int> domains = {AF_INET, AF_INET6};
  std::list<int> types = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
  std::list<int>::iterator dom;

  for (dom = domains.begin(); dom != domains.end(); dom++)
    {
      std::list<int>::iterator typ;
      for (typ = types.begin(); typ != types.end(); typ++)
        {
          if ((*dom == AF_INET6 || *dom == AF_INET) && *typ == SOCK_SEQPACKET)
            {
              continue;
            }
          b->ArgPair(*dom, *typ);
        }
    }
}

static void log_cb(enum sukat_log_lvl lvl, const char *msg)
{
  const bool log_all = false;

  if (lvl == SUKAT_LOG_ERROR || log_all)
    {
      std::cout << msg << std::endl;
    }
}

class SockFixture : public benchmark::Fixture
{
protected:
  SockFixture()
    {
      struct sukat_sock_params params = { };
      struct sukat_sock_cbs cbs = { };

      cbs.log_cb = log_cb;
      ctx = sukat_sock_create(&params, &cbs);
      assert(ctx != NULL);
    }
  virtual ~SockFixture()
    {
      sukat_sock_destroy(ctx);
    }
  sukat_sock_t *ctx;
  const char *localhost6 = "::1";
  const char *localhost = "127.0.0.1";
};

BENCHMARK_DEFINE_F(SockFixture, sock_create)(benchmark::State& st)
{
  while (st.KeepRunning())
    {
      struct sukat_sock_endpoint_params params = { };
      sukat_sock_endpoint_t *endpoint;

      params.domain = st.range_x();
      params.type = st.range_y();
      if (params.domain == AF_INET)
        {
          params.pinet.ip = localhost;
        }
      if (params.domain == AF_INET6)
        {
          params.pinet.ip = localhost6;
        }
      params.server = true;

      endpoint = sukat_sock_endpoint_add(ctx, &params);
      assert(endpoint != NULL);
      sukat_sock_disconnect(ctx, endpoint);
    }
};

struct msg
{
  uint64_t length;
  uint8_t data[];
};

class StreamTest
{
private:
  benchmark::State *state;

  static void *conn_cb(void *caller_ctx, sukat_sock_endpoint_t *endpoint,
                sukat_sock_event_t event)
    {
      StreamTest *ctx = (StreamTest *)caller_ctx;
      if (event == SUKAT_SOCK_CONN_EVENT_ACCEPTED)
        {
          ctx->client_from_server = endpoint;
        }
      else if (event == SUKAT_SOCK_CONN_EVENT_DISCONNECT)
        {
          if (endpoint == ctx->client_from_server)
            {
              ctx->client_from_server = NULL;
            }
          else if (endpoint == ctx->client)
            {
              ctx->client = NULL;
            }
        }
      return NULL;
    }

  static int len_cb(__attribute__((unused)) void *ctx,
                    uint8_t *buf, size_t buf_len)
    {
      if (buf_len >= sizeof(struct msg))
        {
          struct msg *dmsg = (struct msg *)buf;
          return dmsg->length;
        }
      return 0;
    }

  static void msg_cb(void *caller_ctx,
                     __attribute__((unused)) sukat_sock_endpoint_t *endpoint,
                     uint8_t *buf,
                     __attribute__((unused)) size_t buf_len)
    {
      StreamTest *ctx = (StreamTest *)caller_ctx;
      struct msg *dmsg = (struct msg *)buf;

      ctx->state->SetBytesProcessed(ctx->state->bytes_processed() +
                                    dmsg->length);
    }


public:
  sukat_sock_t *ctx;
  sukat_sock_t *client_ctx;
  sukat_sock_endpoint_t *server;
  sukat_sock_endpoint_t *client;
  sukat_sock_endpoint_t *client_from_server;

  StreamTest(const int domain, const int type)
    {
      struct sukat_sock_endpoint_params eparams = { };
      struct sukat_sock_params params = { };
      struct sukat_sock_cbs cbs = { };
      const char *localhost = "127.0.0.1";
      const char *localhost6 = "::1";
      char portbuf[sizeof("65535")];
      char unix_template[] = "/tmp/sukat_benchmark_test_XXXXXX";
      int err;

      eparams.domain = domain;
      eparams.type = type;

      cbs.log_cb = log_cb;
      cbs.conn_cb = conn_cb;
      cbs.msg_cb = msg_cb;
      cbs.msg_len_cb = len_cb;
      params.caller_ctx = this;
      this->ctx = sukat_sock_create(&params, &cbs);
      assert(this->ctx != NULL);
      this->client_ctx = sukat_sock_create(&params, &cbs);

      eparams.server = true;

      switch (eparams.domain)
        {
        case AF_INET:
          eparams.pinet.ip = localhost;
          break;
        case AF_INET6:
          eparams.pinet.ip = localhost6;
          break;
        case AF_UNIX:
          err = mkstemp(unix_template);
          if (err >= 0)
            {
              close(err);
              std::remove(unix_template);
            }
          else
            {
              std::perror("Failed to create temp unix socket name");
              std::abort();
            }
          eparams.punix.is_abstract = true;
          eparams.punix.name = unix_template;
          break;
        default:
          abort();
          break;
        }
      this->server = sukat_sock_endpoint_add(this->ctx, &eparams);
      assert(this->server!= NULL);

      eparams.server = false;
      if (eparams.domain == AF_INET || eparams.domain == AF_INET6)
        {
          snprintf(portbuf, sizeof(portbuf), "%hu",
                   sukat_sock_get_port(this->server));
          eparams.pinet.port = portbuf;
        }
      this->client = sukat_sock_endpoint_add(this->client_ctx, &eparams);
      assert(this->client != NULL);

      err = sukat_sock_read(this->ctx, 100);
      assert(err == 0);
      assert(this->client_from_server != NULL);
      err = sukat_sock_read(this->client_ctx, 100);
      assert(err == 0);
    }

   ~StreamTest()
    {
      if (this->ctx)
        {
          sukat_sock_disconnect(this->ctx, this->server);
          sukat_sock_disconnect(this->client_ctx, this->client);
          sukat_sock_disconnect(this->ctx, this->client_from_server);
          sukat_sock_destroy(this->ctx);
          sukat_sock_destroy(this->client_ctx);
        }
    }

   void set_state(benchmark::State *state)
     {
       this->state = state;
     }
};

BENCHMARK_REGISTER_F(SockFixture, sock_create)->Apply(domain_type_args);

class SockInetStream : public benchmark::Fixture
{
protected:
  SockInetStream()
    {
      teststream = std::make_unique<StreamTest>(AF_INET, SOCK_STREAM);
    }

  virtual ~SockInetStream()
    {
    }
  std::unique_ptr<StreamTest> teststream;

   void set_state(benchmark::State *state)
     {
       teststream->set_state(state);
     }
};

static void run_all_the_way(benchmark::State& st,
                            std::unique_ptr<StreamTest> &teststream,
                            size_t msg_size)
{
  char buf[msg_size];
  enum sukat_sock_send_return send_ret;
  int err;
  struct msg *msghdr = (struct msg *)buf;

  while (st.KeepRunning() && teststream->client)
    {
      msghdr->length = sizeof(buf);
      do
        {
          send_ret = sukat_send_msg(teststream->client_ctx, teststream->client,
                                    (uint8_t *)buf, sizeof(buf), NULL);
        } while (send_ret == SUKAT_SEND_OK);
      assert(send_ret != SUKAT_SEND_ERROR);
      err = sukat_sock_read(teststream->ctx, 100);
      assert(err == 0);
    }
}

BENCHMARK_DEFINE_F(SockInetStream, stream_test_inet)(benchmark::State& st)
{
  set_state(&st);
  run_all_the_way(st, teststream, st.range_x());
}

BENCHMARK_REGISTER_F(SockInetStream,
                     stream_test_inet)->Range(sizeof(struct msg), BUFSIZ);

class SockUnixStream : public benchmark::Fixture
{
protected:
  SockUnixStream()
    {
      teststream = std::make_unique<StreamTest>(AF_UNIX, SOCK_STREAM);
    }

  virtual ~SockUnixStream()
    {
    }
  std::unique_ptr<StreamTest> teststream;

   void set_state(benchmark::State *state)
     {
       teststream->set_state(state);
     }
};

BENCHMARK_DEFINE_F(SockUnixStream, stream_test_unix)(benchmark::State& st)
{
  set_state(&st);
  run_all_the_way(st, teststream, st.range_x());
}

BENCHMARK_REGISTER_F(SockUnixStream,
                     stream_test_unix)->Range(sizeof(struct msg), BUFSIZ);

BENCHMARK_MAIN();
