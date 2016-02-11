#include <iostream>
#include <list>
#include <benchmark/benchmark.h>

extern "C" {
#include "sukat_sock.h"
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

class SockFixture : public benchmark::Fixture
{
public:
  SockFixture()
    {
      struct sukat_sock_params params = { };
      struct sukat_sock_cbs cbs = { };

      ctx = sukat_sock_create(&params, &cbs);
      assert(ctx != NULL);
    }
  ~SockFixture()
    {
      sukat_sock_destroy(ctx);
    }
  void log_cb(enum sukat_log_lvl lvl, const char *msg)
    {
      if (lvl == SUKAT_LOG_ERROR)
        {
          std::cout << msg << std::endl;
        }
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

BENCHMARK_REGISTER_F(SockFixture, sock_create)->Apply(domain_type_args);

BENCHMARK_MAIN();
