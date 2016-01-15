#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sukat_bgp.h"
#include "sukat_util.h"
#include "demo_log.h"

bool keep_running;

struct bgp_query_ctx
{
  uint16_t port;
  uint16_t target_port;
  bgp_id_t id;
  sukat_bgp_t *bgp_ctx;
  const char *target;
  bool only_server;
};

static void usage(const char *binary, const struct option *opts,
                  const char **explanations)
{
  fprintf(stdout,
          "%1$s: Queries a given BGP server\n"
          "Usage: %1$s [<options>] [<bgp_server_ip_or_dns>]\n"
          "       If no target is given, the querier will stay\n"
          "       in server mode\n",
          binary);
  sukat_util_usage(opts, explanations, stdout);
}

static void log_cb(enum sukat_log_lvl lvl, const char *msg)
{
  switch (lvl)
    {
    case SUKAT_LOG_ERROR:
      ERR("%s", msg);
      break;
    case SUKAT_LOG:
      LOG("%s", msg);
      break;
    case SUKAT_LOG_DBG:
      break;
    default:
      abort();
      break;
    }
}

static void *open_cb(__attribute__((unused)) void *ctx,
                     __attribute__((unused)) sukat_bgp_peer_t *peer,
                     bgp_id_t *id, sukat_sock_event_t event)
{
  LOG("BGP peer AS: %hu BGP_ID %u event %s", id->as_num, id->bgp_id,
      (event == SUKAT_SOCK_CONN_EVENT_DISCONNECT) ? "Disconnected" :
      "Connected");
  return NULL;
}

static void keepalive_cb(__attribute__((unused)) void *ctx,
                         __attribute__((unused)) sukat_bgp_peer_t *peer,
                         bgp_id_t *id)
{
  LOG("Got keepalive from %hu %d", id->as_num, id->bgp_id);
}

static int safe_unsigned(char *value_in_ascii, long long int max_size)
{
  int val = atoi(value_in_ascii);

  if (val < 0 || val > max_size)
    {
      ERR("Too big or negative argument %s", value_in_ascii);
      exit(EXIT_FAILURE);
    }

  return val;
}

static bool parse_opts(struct bgp_query_ctx *ctx, int argc, char **argv)
{
  const struct option options[] =
    {
        {"--port", required_argument, NULL, 'p'},
        {"--target-port", required_argument, NULL, 't'},
        {"--as", required_argument, NULL, 'a'},
        {"--bgp", required_argument, NULL, 'b'},
        {"--help", no_argument, NULL, 'h'},
        {}
    };
  const char *explanations[] =
    {
      "Port from which to initialize connection",
      "Targets port. Default 179",
      "AS number sent to target",
      "BGP ID sent to target",
      "Print this help",
    };
  _Static_assert(sizeof(explanations) / sizeof (*explanations) ==
                 sizeof(options) / sizeof(*options) - 1,
                 "Please update explanations");
  int c, what;
  optind = 1;

  while ((c = getopt_long(argc, argv, "p:a:b:t:h", options, &what)) != -1)
    {
      switch (c)
        {
        case 'p':
          ctx->port = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 'a':
          ctx->id.as_num = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 'b':
          ctx->id.bgp_id = safe_unsigned(optarg, UINT32_MAX);
          break;
        case 't':
          ctx->target_port = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 'h':
        default:
          goto fail;
          break;
        }
    }
  if (optind < argc)
    {
      ctx->target = argv[optind];
    }
  else
    {
      ctx->only_server = true;
    }
  return true;

fail:
  usage(argv[0], options, explanations);
  return false;
}

int main(int argc, char **argv)
{
  int exit_val = EXIT_FAILURE;
  struct bgp_query_ctx ctx =
    {
      .port = 179,
      .target_port = 179,
    };

  if (parse_opts(&ctx, argc, argv) == true)
    {
      char portbuf[strlen("65536") + 1];
      struct bgp_query_ctx query_ctx = { };
      struct sukat_bgp_params params =
        {
          .id = ctx.id,
          .pinet =
            {
              .ip = NULL,
              .port = portbuf
            },
          .caller_ctx = &query_ctx
        };
      struct sukat_bgp_cbs cbs =
        {
          .log_cb = log_cb,
          .keepalive_cb = keepalive_cb,
          .open_cb = open_cb
        };
      sukat_bgp_t *bgp_ctx;

      snprintf(portbuf, sizeof(portbuf), "%u", ctx.port);
      bgp_ctx = sukat_bgp_create(&params, &cbs);
      if (bgp_ctx)
        {
          char target_port_buf[sizeof(portbuf)];
          struct sukat_sock_params_inet peer_inet =
            {
              .ip = ctx.target,
              .port = target_port_buf,
            };
          sukat_bgp_peer_t *peer = NULL;

          query_ctx.bgp_ctx = bgp_ctx;

          snprintf(target_port_buf, sizeof(target_port_buf), "%u",
                   ctx.target_port);
          if (ctx.only_server ||
              (peer = sukat_bgp_peer_add(bgp_ctx, &peer_inet)) != NULL)
            {
              keep_running = true;
              exit_val = EXIT_SUCCESS;

              while (keep_running)
                {
                  int err = sukat_bgp_read(bgp_ctx, 1000);

                  if (err < 0)
                    {
                      keep_running = false;
                    }
                }
              if (peer)
                {
                  sukat_bgp_disconnect(bgp_ctx, peer);
                }
            }
          sukat_bgp_destroy(bgp_ctx);
        }
    }
  return exit_val;
}
