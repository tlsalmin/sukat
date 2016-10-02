#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/epoll.h>

#include "sukat_sock.h"
#include "sukat_util.h"
#include "tools_log.h"
#include "tools_common.h"

struct netdoge_ctx
{
  sukat_sock_t *sock_ctx;
  sukat_sock_endpoint_t *target;
  sukat_sock_endpoint_t *source;
    int epoll_fd;
  int send_pipes[2];
  int read_pipes[2];
  sukat_sock_endpoint_t *client;
  struct sukat_sock_endpoint_params target_params;
  struct
    {
      unsigned int connected:1; /*!< Either server has atleast one client or
                                     the client has connected */
      unsigned int unused:7;
    };
};

uint8_t log_level = 0;

static void usage(const char *binary, const struct option *opts,
                  const char **explanations)
{
  fprintf(stderr,
          "%1$s: Connect to an endpoint\n"
          "Usage: %1$s [<options>] <endpoint identifier>\n", binary);
  sukat_util_usage(opts, explanations, stderr);
}

static bool parse_target_string(struct netdoge_ctx *doge_ctx,
                                const char *target_string)
{
  char tmp[BUFSIZ], *ptr; // Kinda random length, but yeah.

  snprintf(tmp, sizeof(tmp), "%s", target_string);

  // Ignoring all strdup allocations here, since meh
  switch (doge_ctx->target_params.domain)
    {
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      /* Target string should be <dns-name-or-ip>[,<port>] */
      if ((ptr = strchr(tmp, ',')) != NULL)
        {
          *ptr = '\0';
          ptr++;
          if (strlen(ptr) > 0 && safe_unsigned(ptr, UINT16_MAX) > 0)
            {
              doge_ctx->target_params.pinet.port = strdup(ptr);
            }
        }
      doge_ctx->target_params.pinet.ip = strdup(tmp);
      break;
    case AF_UNIX:
      /* Target string should be <path>[,abstract] */
      if ((ptr = strchr(tmp, ',')) != NULL)
        {
          *ptr = '\0';
          ptr++;
          if (strcmp(ptr, "abstract"))
            {
              doge_ctx->target_params.punix.is_abstract = true;
            }
        }
      doge_ctx->target_params.punix.name = strdup(tmp);
      break;
    case AF_TIPC:
      ptr = strchr(tmp, ',');
      if (!ptr)
        {
          ERR("Missing port for TIPC");
          return false;
        }
      *ptr = '\0';
      ptr++;
      doge_ctx->target_params.ptipc.port_type = safe_unsigned(tmp, UINT32_MAX);
      doge_ctx->target_params.ptipc.port_instance =
        safe_unsigned(tmp, UINT32_MAX);
      break;
    default:
      abort();
      break;
    }
  return true;
}

static bool parse_opts(struct netdoge_ctx *doge_ctx, int argc, char **argv)
{
  int c, what;
  const struct option options[] =
    {
        {"listen", no_argument, NULL, 'l'},
        {"unix", no_argument, NULL, 'u'},
        {"tipc", no_argument, NULL, 't'},
        {"ipv6", no_argument, NULL, '6'},
        {"ipv4", no_argument, NULL, '4'},
        {"dgram", no_argument, NULL, 'g'},
        {"seqpacket", no_argument, NULL, 'e'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {},
    };
  const char *explanations[] =
    {
      "Listen instead of connecting",
      "Use a AF_UNIX socket. Adding ,abstract after path for abstract socket.",
      "Use a TIPC socket",
      "Use a IPv6 socket",
      "Use a IPv4 socket",
      "Use a datagram socket type",
      "Use a seqpacket socket type",
      "Verbose output. Two verboses give debug information",
      "Print this help",
    };

  _Static_assert(sizeof(explanations) / sizeof (*explanations) ==
                 sizeof(options) / sizeof(*options) - 1,
                 "Please update explanations");

  while((c = getopt_long(argc, argv, "lhut64gve", options, &what)) != -1)
    {
      switch (c)
        {
        case 'l':
          doge_ctx->target_params.server = true;
          break;
        case 'u':
          doge_ctx->target_params.domain = AF_UNIX;
          break;
        case 't':
          doge_ctx->target_params.domain = AF_TIPC;
          break;
        case '6':
          doge_ctx->target_params.domain = AF_INET6;
          break;
        case '4':
          doge_ctx->target_params.domain = AF_INET;
          break;
        case 'g':
          doge_ctx->target_params.type = SOCK_DGRAM;
          break;
        case 'v':
          log_level++;
          break;
        case 'e':
          doge_ctx->target_params.type = SOCK_SEQPACKET;
          break;
        default:
          ERR("Unknown argument %c", c);
        case 'h':
          goto fail;
          break;
        }
    }
  if (optind < argc)
    {
      if (parse_target_string(doge_ctx, argv[optind]) != true)
        {
          goto fail;
        }
    }
  else if (doge_ctx->target_params.server == false)
    {
      ERR("No target given for non-server doge");
      goto fail;
    }

  return true;

fail:
  usage(argv[0], options, explanations);
  return false;
}

static void log_cb(enum sukat_log_lvl lvl, const char *msg)
{
  if (log_level >= 2 || (lvl == SUKAT_LOG && log_level == 1) ||
      (lvl == SUKAT_LOG_ERROR))
    {
      fprintf(stderr, "%s\n", msg);
    }
}

static void splice_cb(void *ctx,
                      __attribute__((unused))sukat_sock_endpoint_t *endpoint,
                      int *target_fd, int **intermediary_fds)
{
  struct netdoge_ctx *doge_ctx = (struct netdoge_ctx *)ctx;

  *target_fd = STDOUT_FILENO;
  *intermediary_fds = doge_ctx->read_pipes;
}

static void *conn_cb(void *caller_ctx, sukat_sock_endpoint_t *endpoint,
                     sukat_sock_event_t event)
{
  struct netdoge_ctx *ctx = (struct netdoge_ctx *)caller_ctx;

  assert(ctx != NULL);
  if (event == SUKAT_SOCK_CONN_EVENT_CONNECT)
    {
      ctx->connected = true;
    }
  else if (event == SUKAT_SOCK_CONN_EVENT_ACCEPTED)
    {
      ctx->client = endpoint;
      ctx->connected = true;
    }
  else
    {
      ctx->connected = false;
      // client already destroyed if this doge is running as server.
      ctx->client = NULL;
      if (!ctx->target_params.server)
        {
          ctx->target = NULL;
        }
      keep_running = false;
    }
  return NULL;
}

static bool run_loop(struct netdoge_ctx *doge_ctx)
{
  bool retval = true;

  while (!doge_ctx->connected && keep_running)
    {
      // Timeout on TCP connect
      int err = sukat_sock_read(doge_ctx->sock_ctx, 1000);
      if (err != 0)
        {
          keep_running = false;
        }
    }

  while (keep_running)
    {
      struct epoll_event events[2];
      int ret;

      ret = epoll_wait(doge_ctx->epoll_fd, events, 2, -1);
      if (ret == -1)
        {
          if (errno != EINTR)
            {
              ERR("Failed to wait for events: %s", strerror(errno));
              return false;
            }
        }
      else if (ret == 0)
        {
          // Shouldn't happen
          abort();
        }
      else
        {
          unsigned int i;
          sukat_sock_endpoint_t *endpoint =
            (doge_ctx->client) ? doge_ctx->client : doge_ctx->target;

          assert(endpoint != NULL);
          for (i = 0; i < (unsigned int)ret; i++)
            {
              if (events[i].data.fd == STDIN_FILENO)
                {
                  if (events[i].events & EPOLLIN)
                    {
                      ssize_t send_ret =
                        sukat_sock_splice_to(doge_ctx->sock_ctx, endpoint,
                                             STDIN_FILENO, doge_ctx->send_pipes);
                      if (send_ret < 0)
                        {
                          return false;
                        }
                    }
                  else if ((events[i].events & ~EPOLLIN))
                    {
                      if (log_level)
                        {
                          LOG("Stdin closed. Exiting");
                        }
                      return false;
                    }
                }
              else
                {
                  if (sukat_sock_read(doge_ctx->sock_ctx, 0) != 0)
                    {
                      return false;
                    }
                }
            }
        }
    }

  return retval;
}

bool init_fds(struct netdoge_ctx *doge_ctx)
{
  if ((doge_ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) >= 0)
    {
      // TODO: Investigate this new O_DIRECT I found in man-page.
      if (pipe2(doge_ctx->read_pipes, O_CLOEXEC | O_NONBLOCK) == 0)
        {
          if (pipe2(doge_ctx->send_pipes, O_CLOEXEC | O_NONBLOCK) == 0)
            {
              if (!sukat_util_flagit(STDIN_FILENO) &&
                  !sukat_util_flagit(STDOUT_FILENO))
                {
                  return true;
                }
              else
                {
                  ERR("Failed to set flags to stdin and stdout: %s",
                      strerror(errno));
                }
              close(doge_ctx->send_pipes[0]);
              close(doge_ctx->send_pipes[1]);
            }
          close(doge_ctx->read_pipes[0]);
          close(doge_ctx->read_pipes[1]);
        }
      close(doge_ctx->epoll_fd);
    }
  ERR("Failed to initialize fds: %s", strerror(errno));
  return false;
}

void close_fds(struct netdoge_ctx *doge_ctx)
{
  close(doge_ctx->epoll_fd);
  close(doge_ctx->read_pipes[0]);
  close(doge_ctx->read_pipes[1]);
  close(doge_ctx->send_pipes[0]);
  close(doge_ctx->send_pipes[1]);
}

int main(int argc, char **argv)
{
  struct netdoge_ctx doge_ctx = { };
  int retval = EXIT_FAILURE;

  // Default values
  doge_ctx.target_params.domain = AF_UNSPEC;
  doge_ctx.target_params.type = SOCK_STREAM;

  if (parse_opts(&doge_ctx, argc, argv) == true)
    {
      if (init_fds(&doge_ctx) == true)
        {
          struct sukat_sock_params sock_params = { };
          struct sukat_sock_cbs sock_cbs = { };

          sock_params.master_epoll_fd = doge_ctx.epoll_fd;
          sock_params.master_epoll_fd_set = true;
          if (log_level)
            {
              sock_cbs.log_cb = log_cb;
            }
          sock_cbs.conn_cb = conn_cb;
          sock_cbs.splice_cb = splice_cb;
          sock_params.caller_ctx = &doge_ctx;

          if ((doge_ctx.sock_ctx = sukat_sock_create(&sock_params, &sock_cbs)))
            {
              doge_ctx.target =
                sukat_sock_endpoint_add(doge_ctx.sock_ctx,
                                        &doge_ctx.target_params);
              if (doge_ctx.target)
                {
                  if (log_level)
                    {
                      LOG("Succesfully %s!",
                          (doge_ctx.target_params.server) ? "listening" :
                          "connected");
                    }
                  keep_running = true;

                  if (simple_sighandler() == true)
                    {
                      struct epoll_event ev =
                        {
                          .events = EPOLLIN,
                          .data =
                            {
                              .fd = STDIN_FILENO
                            }
                        };

                      if (!epoll_ctl(doge_ctx.epoll_fd, EPOLL_CTL_ADD,
                                     STDIN_FILENO, &ev))
                        {
                          if (run_loop(&doge_ctx) == true)
                            {
                              retval = EXIT_SUCCESS;
                            }
                          epoll_ctl(doge_ctx.epoll_fd, EPOLL_CTL_DEL,
                                    STDIN_FILENO, &ev);
                        }
                      else
                        {
                          ERR("Failed to poll stdin: %s", strerror(errno));
                        }
                      if (doge_ctx.client)
                        {
                          sukat_sock_disconnect(doge_ctx.sock_ctx,
                                                doge_ctx.client);
                        }
                    }

                  sukat_sock_disconnect(doge_ctx.sock_ctx, doge_ctx.target);
                }
              sukat_sock_destroy(doge_ctx.sock_ctx);
              doge_ctx.sock_ctx = NULL;
            }
          else
            {
              ERR("Failed o create socket context");
            }
          close_fds(&doge_ctx);
        }
      else
        {
          ERR("Failed to create master epoll fd: %s", strerror(errno));
        }
      // This is kinda annoying
      if (doge_ctx.target_params.domain == AF_INET ||
          doge_ctx.target_params.domain == AF_INET6 ||
          doge_ctx.target_params.domain == AF_UNSPEC)
        {
          free((void *)doge_ctx.target_params.pinet.ip);
          free((void *)doge_ctx.target_params.pinet.port);
        }
      else if (doge_ctx.target_params.domain == AF_UNIX)
        {
          free((void *)doge_ctx.target_params.punix.name);
        }
    }
  return retval;
}
