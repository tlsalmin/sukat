#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sukat_bgp.h"
#include "demo_log.h"

bool keep_running;

struct bgp_query_ctx
{
  sukat_bgp_t *bgp_ctx;
};

static void usage(const char *binary)
{
  fprintf(stdout,
          "%1$s: Queries a given BGP server\n"
          "Usage: %1$s [<options>] <bgp_server_ip_or_dns>\n\n"
          "flags:",
          binary);
  exit(EXIT_FAILURE);
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
      (event == SUKAT_SOCK_CONN_EVENT_CONNECT) ? "Connected" : "Disconnected");
  return NULL;
}

static void keepalive_cb(void *ctx,
                         sukat_bgp_peer_t *peer,
                         bgp_id_t *id)
{
  struct bgp_query_ctx *query_ctx = (struct bgp_query_ctx *)ctx;

  LOG("Got keepalive from %hu %d", id->as_num, id->bgp_id);
  sukat_bgp_send_keepalive(query_ctx->bgp_ctx, peer);
}

static int safe_unsigned(char *value_in_ascii, int max_size)
{
  int val = atoi(value_in_ascii);

  if (val < 0 || val > max_size)
    {
      ERR("Too big or small argument %s", value_in_ascii);
      exit(EXIT_FAILURE);
    }

  return val;
}

int main(int argc, char **argv)
{
  struct option opts[] =
    {
        {"--port", required_argument, NULL, 0},
        {"--target-port", required_argument, NULL, 0},
        {"--as", required_argument, NULL, 0},
        {"--bgp", required_argument, NULL, 0}
    };
  int opt, opt_ind;
  uint16_t port = 179, target_port = 179;
  int exit_val = EXIT_FAILURE;
  bgp_id_t id = { };

  while ((opt = getopt_long(argc, argv, "p:a:b:t:", opts, &opt_ind)) != -1)
    {
      switch (opt)
        {
        case 'p':
          port = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 'a':
          id.as_num = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 'b':
          id.bgp_id = safe_unsigned(optarg, UINT32_MAX);
          break;
        case 't':
          target_port = safe_unsigned(optarg, UINT16_MAX);
          break;
        default:
          usage(argv[0]);
          break;
        }
    }
  if (optind < argc)
    {
      char portbuf[strlen("65536") + 1];
      const char *target = argv[optind];
      struct bgp_query_ctx query_ctx = { };
      struct sukat_bgp_params params =
        {
          .id = id,
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

      snprintf(portbuf, sizeof(portbuf), "%u", port);
      bgp_ctx = sukat_bgp_create(&params, &cbs);
      if (bgp_ctx)
        {
          char target_port_buf[sizeof(portbuf)];
          struct sukat_sock_params_inet peer_inet =
            {
              .ip = target,
              .port = target_port_buf,
            };
          sukat_bgp_peer_t *peer;

          query_ctx.bgp_ctx = bgp_ctx;

          snprintf(target_port_buf, sizeof(target_port), "%u", target_port);
          peer = sukat_bgp_peer_add(bgp_ctx, &peer_inet);
          if (peer != NULL)
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
              sukat_bgp_disconnect(bgp_ctx, peer);
            }
          sukat_bgp_destroy(bgp_ctx);
        }
    }
  else
    {
      ERR("No target given");
      usage(argv[0]);
    }
  return exit_val;
}
