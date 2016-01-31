#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "sukat_bgp.h"
#include "sukat_util.h"
#include "tools_log.h"
#include <arpa/inet.h>
#include <netinet/in.h>

bool keep_running;

struct bgp_query_ctx
{
  uint16_t port;
  uint16_t target_port;
  bgp_id_t id;
  sukat_bgp_t *bgp_ctx;
  const char *target;
  const char *bgp_string;
  bool only_server;
};

static void usage(const char *binary, const struct option *opts,
                  const char **explanations)
{
  fprintf(stdout,
          "%1$s: Queries a given BGP server\n"
          "Usage: %1$s [<options>] <bgp_server_ip_or_dns>\n"
          "       Target is either bound in server mode or\n"
          "       connected to in client mode\n",
          binary);
  sukat_util_usage(opts, explanations, stdout);
}

static void log_cb(enum sukat_log_lvl lvl, const char *msg)
{
  switch (lvl)
    {
    case SUKAT_LOG_ERROR:
      fprintf(stderr, "%s\n", msg);
      break;
    case SUKAT_LOG:
      fprintf(stdout, "%s\n", msg);
      break;
    case SUKAT_LOG_DBG:
      break;
    default:
      abort();
      break;
    }
}

static void *open_cb(__attribute__((unused)) void *ctx,
                     sukat_bgp_peer_t *peer, sukat_sock_event_t event)
{
  char ipstr[INET6_ADDRSTRLEN];
  const bgp_id_t *id = sukat_bgp_get_bgp_id(peer);
  uint32_t address = htonl(id->bgp_id);

  LOG("BGP peer AS: %hu BGP_ID %s event %s", id->as_num,
      inet_ntop(AF_INET, &address, ipstr, sizeof(ipstr)),
      (event == SUKAT_SOCK_CONN_EVENT_DISCONNECT) ? "Disconnected" :
      "Connected");
  return NULL;
}

static void keepalive_cb(__attribute__((unused)) void *ctx,
                         sukat_bgp_peer_t *peer)
{
  char ipstr[INET6_ADDRSTRLEN];
  const bgp_id_t *id = sukat_bgp_get_bgp_id(peer);
  uint32_t address = htonl(id->bgp_id);

  LOG("Got keepalive from %hu %s", id->as_num,
      inet_ntop(AF_INET, &address, ipstr, sizeof(ipstr)));
}

static void log_prefixes(void *start, const char *type, size_t length)
{
  char ipstr[INET6_ADDRSTRLEN];
  size_t parsed;

  for (parsed = 0; parsed < length;)
    {
      struct sukat_bgp_lp *lp = (struct sukat_bgp_lp *)start + parsed;
      uint32_t prefix = 0;
      size_t copy_len = 0;

      if (lp->length > 0)
        {
          copy_len = 1 + (lp->length - 1) / 8;
        }
      if (copy_len > 4)
        {
          ERR("Illegal copy request of %lu bytes", copy_len);
          return;
        }
      else
        {
          if (copy_len)
            {
              memcpy(&prefix, lp->prefix, copy_len);
            }
          LOG("%s prefix %s/%u", type,
              inet_ntop(AF_INET, &prefix, ipstr, sizeof(ipstr)), lp->length);

        }
      parsed += 1 + copy_len;
    }
}

static void update_cb(__attribute__((unused)) void *ctx,
                      __attribute__((unused)) sukat_bgp_peer_t *peer,
                      struct sukat_bgp_update *update)
{
  char ipstr[INET6_ADDRSTRLEN];
  const bgp_id_t *id = sukat_bgp_get_bgp_id(peer);
  uint32_t address = htonl(id->bgp_id);
  struct sukat_bgp_path_attr *path_attr = update->path_attr;
  size_t i;

  LOG("Got update from %hu %s", id->as_num,
      inet_ntop(AF_INET, &address, ipstr, sizeof(ipstr)));
  log_prefixes(update->withdrawn, "Withdrawn", update->withdrawn_length);
  log_prefixes(update->reachability, "Reachable", update->reachability_length);

  while (path_attr)
    {
      LOG("Flags: extended: %hhu partial: %hhu transitive %hhu optional %hhu",
          path_attr->flags.extended, path_attr->flags.partial,
          path_attr->flags.transitive, path_attr->flags.optional);
      switch (path_attr->attr_type)
        {
        case SUKAT_BGP_ATTR_ORIGIN:
          LOG("Origin: %hhu", path_attr->value.origin);
          break;
        case SUKAT_BGP_ATTR_AS_PATH:
          LOG("AS_PATH: AS_%s", (path_attr->value.as_path.type == SUKAT_BGP_AS_SET) ?
              "SET" : "SEQUENCE");
          for (i = 0; i < path_attr->value.as_path.number_of_as_numbers; i++)
            {
              LOG("AS number %hu", path_attr->value.as_path.as_numbers[i]);
            }
          break;
        case SUKAT_BGP_ATTR_NEXT_HOP:
          address = htonl(path_attr->value.next_hop);
          LOG("Next hop %s",
              inet_ntop(AF_INET, &address, ipstr, sizeof(ipstr)));
          break;
        case SUKAT_BGP_ATTR_MULTI_EXIT_DISC:
          LOG("Multi exit disc %u", path_attr->value.multi_exit_disc);
          break;
        case SUKAT_BGP_ATTR_LOCAL_PREF:
          LOG("Local pref %u", path_attr->value.local_pref);
          break;
        case SUKAT_BGP_ATTR_ATOMIC_AGGREGATE:
          LOG("Atomic Aggregate");
          break;
        case SUKAT_BGP_ATTR_AGGREGATOR:
          address = htonl(path_attr->value.aggregator.ip);
          LOG("Aggregator: AS number: %hu IP: %s",
              path_attr->value.aggregator.as_number,
              inet_ntop(AF_INET, &address, ipstr, sizeof(ipstr)));
          break;
        default:
          ERR("Unknown type %u", path_attr->attr_type);
          break;
        }
      path_attr = path_attr->next;
    }
}

static void notification_cb(__attribute__((unused)) void *ctx,
                            sukat_bgp_peer_t *peer,
                            uint8_t error_code, uint8_t subcode,
                            uint8_t *data, size_t data_len)
{
  char ipstr[INET6_ADDRSTRLEN];
  const bgp_id_t *id = sukat_bgp_get_bgp_id(peer);
  uint32_t address = htonl(id->bgp_id);

  LOG("Got Notification from %hu %s. Code %hhu subcode %hhu", id->as_num,
      inet_ntop(AF_INET, &address, ipstr, sizeof(ipstr)), error_code,
      subcode);
  if (data && data_len)
    {
      char data_buffer[data_len + 1];

      memcpy(data_buffer, data, data_len);
      data_buffer[data_len] = '\0';
      LOG("Notification contained data \"%s\"", data_buffer);
    }
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
        {"--server", no_argument, NULL, 's'},
        {"--help", no_argument, NULL, 'h'},
        {}
    };
  const char *explanations[] =
    {
      "Port from which to initialize connection",
      "Targets port. Default 179",
      "AS number sent to target",
      "BGP ID sent to target",
      "Act as server only",
      "Print this help",
    };
  _Static_assert(sizeof(explanations) / sizeof (*explanations) ==
                 sizeof(options) / sizeof(*options) - 1,
                 "Please update explanations");
  int c, what;
  optind = 1;

  while ((c = getopt_long(argc, argv, "p:a:b:t:hs", options, &what)) != -1)
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
          ctx->bgp_string = optarg;
          break;
        case 't':
          ctx->target_port = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 's':
          ctx->only_server = true;
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
  else if (ctx->only_server == false)
    {
      ERR("No target given for non-server BGP querier");
      goto fail;
    }
  return true;

fail:
  usage(argv[0], options, explanations);
  return false;
}

static void sighandler(int siggie)
{
  LOG("Received signal %d", siggie);
  keep_running = false;
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
              .ip = (ctx.only_server) ? ctx.target : NULL,
              .port = portbuf
            },
          .bgp_id_str = ctx.bgp_string,
          .caller_ctx = &query_ctx
        };
      struct sukat_bgp_cbs cbs =
        {
          .log_cb = log_cb,
          .keepalive_cb = keepalive_cb,
          .update_cb = update_cb,
          .notification_cb = notification_cb,
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
              struct sigaction old_action, new_action =
                {
                  .sa_handler = sighandler,
                };

              if (!sigaction(SIGINT, &new_action, &old_action))
                {
                  exit_val = EXIT_SUCCESS;

                  while (keep_running)
                    {
                      int err = sukat_bgp_read(bgp_ctx, 1000);

                      if (err < 0)
                        {
                          keep_running = false;
                        }
                    }
                  if (sigaction(SIGINT, &old_action, NULL))
                    {
                      ERR("Failed to restore signal handler: %s",
                          strerror(errno));
                    }
                }
              else
                {
                  ERR("Failed to set signal handler: %s", strerror(errno));
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
