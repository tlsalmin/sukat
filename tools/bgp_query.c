#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include "sukat_bgp.h"
#include "sukat_util.h"
#include "tools_log.h"
#include "tools_common.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>

struct bgp_query_ctx
{
  uint16_t port;
  uint16_t target_port;
  const char *as_num; //!< Range or single as number.
  sukat_bgp_t *bgp_ctx;
  const char *target;
  const char *bgp_id;
  const char *source; //!< Source IP for connection to peer.
  bool only_server;
  unsigned int n_connections;
};

bool verbose = false;

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
    case SUKAT_LOG_DBG:
      if (!verbose)
        break;
    case SUKAT_LOG:
      fprintf(stdout, "%s\n", msg);
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

static bool parse_opts(struct bgp_query_ctx *ctx, int argc, char **argv)
{
  const struct option options[] =
    {
        {"port", required_argument, NULL, 'p'},
        {"target-port", required_argument, NULL, 't'},
        {"as", required_argument, NULL, 'a'},
        {"bgp", required_argument, NULL, 'b'},
        {"server", no_argument, NULL, 's'},
        {"connections", required_argument, NULL, 'n'},
        {"source", required_argument, NULL, 'S'},
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        {}
    };
  const char *explanations[] =
    {
      "Port from which to initialize connection",
      "Targets port. Default 179",
      "AS number sent to target",
      "BGP ID sent to target. Defaults to Source IP if set",
      "Act as server only",
      "Number of connections. Defaults to 1. Max is UINT16_MAX",
      "Source IP address",
      "Print this help",
      "Increase verbosity",
    };
  _Static_assert(sizeof(explanations) / sizeof (*explanations) ==
                 sizeof(options) / sizeof(*options) - 1,
                 "Please update explanations");
  int c, what;
  optind = 1;

  while ((c = getopt_long(argc, argv, "p:a:b:t:hsn:S:v", options, &what)) != -1)
    {
      switch (c)
        {
        case 'p':
          ctx->port = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 'a':
          ctx->as_num = optarg;
          break;
        case 'b':
          ctx->bgp_id = optarg;
          break;
        case 't':
          ctx->target_port = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 's':
          ctx->only_server = true;
          break;
        case 'n':
          ctx->n_connections = safe_unsigned(optarg, UINT16_MAX);
          break;
        case 'S':
          ctx->source = optarg;
          break;
        case 'v':
          verbose = true;
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

static void main_loop(sukat_bgp_t *bgp_ctx, int efd, int sigfd)
{
  bool keep_running = true;
  struct epoll_event ev;
  int ret;

  while (keep_running && (ret = epoll_wait(efd, &ev, 1, -1)) > 0)
    {
      if (ev.data.fd == sigfd)
        {
          int sig_received = simple_sighandler_read_signal(sigfd);

          switch (sig_received)
            {
              case SIGPIPE:
              case 0:
                break;
              default:
                keep_running = false;
                break;
            }
        }
      else
        {
          assert(ev.data.fd == sukat_bgp_get_epoll(bgp_ctx));
          int err = sukat_bgp_read(bgp_ctx, 1000);

          if (err < 0)
            {
              keep_running = false;
            }
        }
    }
}

static bool add_peers(sukat_bgp_t *bgp_ctx, const unsigned int n_peers,
                      const struct sukat_sock_params_inet *peer_inet,
                      sukat_bgp_peer_t **peer_array, const char *sources,
                      const char *as_numbers)
{
  unsigned int i;
  bool one_succeeded = false;
  struct sukat_util_range_values range_source = {}, range_as = {};

  if (sources && !sukat_util_range_to_integers(
                   sources, SUKAT_UTIL_RANGE_INPUT_IP, &range_source))
    {
      ERR("Failed to convert %s to an IP range", sources);
    }
  else if (as_numbers &&
           !sukat_util_range_to_integers(
             as_numbers, SUKAT_UTIL_RANGE_INPUT_INTEGER, &range_as))
    {
      ERR("Failed to convert %s to an integer range", as_numbers);
    }
  if (n_peers > 0 && !sukat_util_file_limit_increase(n_peers))
    {
      ERR("Failed to increase file limit to at least %u: %m", n_peers);
    }
  else
    {
      for (i = 0; i < n_peers; i++)
        {
          bgp_id_t id = {};
          const char *port = "0";
          char ipstr[INET6_ADDRSTRLEN];
          const struct sukat_sock_params_inet src = {.ip = ipstr, .port = port};

          if (sources)
            {
              if (range_source.type == SUKAT_UTIL_RANGE_VALUE_4BYTE)
                {
                  uint32_t source =
                    htonl(range_source.start4 + (i % range_source.count4));

                  if (!inet_ntop(AF_INET, &source, ipstr, sizeof(ipstr)))
                    {
                      ERR("Failed to convert %u back to IP: %m", source);
                    }
                  else
                    {
                      LOG("Prebinding connection to %s", src.ip);
                    }
                  id.bgp_id = ntohl(source);
                }
              else
                {
                  __int128 source = sukat_util_ntohlll(
                    range_source.start16 + (i % range_source.count16));
                  if (!inet_ntop(AF_INET6, &source, ipstr, sizeof(ipstr)))
                    {
                      // Some printf to see it meh.
                      ERR("Failed to convert back to IP: %m");
                    }
                  id.bgp_id = ntohl(source & 0xffffffff);
                  LOG("Using AS number %u", id.bgp_id);
                }
            }
          if (as_numbers)
            {
              id.as_num = range_as.start4 + (i % range_as.count4);
            }

          peer_array[i] = sukat_bgp_peer_add(
            bgp_ctx, peer_inet, sources ? &src : NULL, as_numbers ? &id : NULL);
          if (peer_array[i] != NULL)
            {
              one_succeeded = true;
            }
        }
    }
  return one_succeeded;
}

int main(int argc, char **argv)
{
  int exit_val = EXIT_FAILURE;
  struct bgp_query_ctx ctx =
    {
      .port = 179,
      .target_port = 179,
      .n_connections = 1
    };

  if (parse_opts(&ctx, argc, argv) == true)
    {
      char portbuf[strlen("65536") + 1];
      struct bgp_query_ctx query_ctx = { };
      char *delimiter;
      struct sukat_bgp_params params =
        {
          .pinet =
            {
              .ip = (ctx.only_server) ? ctx.target : NULL,
              .port = portbuf
            },
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

      if (ctx.bgp_id && !strchr(ctx.bgp_id, '-'))
        {
          params.bgp_id_str = ctx.bgp_id;
        }
      else if (ctx.source && !strchr(ctx.source, '-'))
        {
          params.bgp_id_str = ctx.source;
        }
      // else there must be a range of ids.

      if ((delimiter = strchr(ctx.as_num, '-')))
        {
          char buf[BUFSIZ] = { };

          // use the first.
          strncat(buf, ctx.as_num, delimiter - ctx.as_num - 1);
          params.id.as_num = safe_unsigned(buf, UINT32_MAX);
        }
      else
        {
          params.id.as_num = safe_unsigned(ctx.as_num, UINT32_MAX);
        }

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
          sukat_bgp_peer_t *peers[ctx.n_connections];

          memset(peers, 0, sizeof(peers));
          query_ctx.bgp_ctx = bgp_ctx;

          snprintf(target_port_buf, sizeof(target_port_buf), "%u",
                   ctx.target_port);
          if (ctx.only_server ||
              add_peers(bgp_ctx, ctx.n_connections, &peer_inet, peers,
                        ctx.source, ctx.as_num))
            {
              sigset_t sigs;
              int sigfd;

              sigemptyset(&sigs);
              sigaddset(&sigs, SIGPIPE);

              if ((sigfd = simple_sighandler(&sigs)) >= 0)
                {
                  int efd = epoll_create1(EPOLL_CLOEXEC);

                  if (efd >= 0)
                    {
                      struct epoll_event ev[] = {
                        {
                          .events = EPOLLIN,
                          .data.fd = sukat_bgp_get_epoll(bgp_ctx),
                        },
                        {.events = EPOLLIN, .data.fd = sigfd}};

                      if (!epoll_ctl(efd, EPOLL_CTL_ADD,
                                     sukat_bgp_get_epoll(bgp_ctx), &ev[0]) &&
                          !epoll_ctl(efd, EPOLL_CTL_ADD, sigfd, &ev[1]))
                        {
                          exit_val = EXIT_SUCCESS;
                          main_loop(bgp_ctx, efd, sigfd);
                        }
                      if (close(efd))
                        {
                          ERR("Failed to close eventfd: %m");
                        }
                    }
                  if (close(sigfd))
                    {
                      ERR("Failed to close signalfd: %m");
                    }
                }
              {
                unsigned int i;

                for (i = 0; i < ctx.n_connections; i++)
                  {
                    if (peers[i])
                      {
                        sukat_bgp_disconnect(bgp_ctx, peers[i]);
                      }
                  }
              }
            }
          sukat_bgp_destroy(bgp_ctx);
        }
    }
  return exit_val;
}
