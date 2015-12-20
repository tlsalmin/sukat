/*!
 * @file sukat_event.h
 * @brief Event loop implementation for the sukat API.
 *
 * @addtogroup sukat_event
 * @{
 */
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <stdlib.h>

#include "sukat_event.h"
#include "sukat_log_internal.h"

struct ecall_ctx
{
  sukat_event_cb cb;
  void *cb_ctx;
  int fd;
};


struct sukat_event_ctx
{
  struct sukat_event_cbs cbs;
  int epoll_fd;
  size_t n_fds; //!< Number of events registered.
};

sukat_event_ctx_t *sukat_event_create(struct sukat_event_params *params,
                                      struct sukat_event_cbs *cbs)
{
  sukat_event_ctx_t *ctx;

  ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    {
      return NULL;
    }
  if (cbs)
    {
      memcpy(&ctx->cbs, cbs, sizeof(*cbs));
    }

  (void)params;
  ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (ctx->epoll_fd < 0)
    {
      ERR(ctx, "Failed to create epoll instance: %s", strerror(errno));
      free(ctx);
      return NULL;
    }
  DBG(ctx, "Created event context %p", ctx);
  return ctx;
};

void sukat_event_destroy(sukat_event_ctx_t *ctx)
{
  if (ctx)
    {
      DBG(ctx, "Destroying event ctx %p", ctx);
      if (ctx->epoll_fd >= 0)
        {
          close(ctx->epoll_fd);
        }
      free(ctx);
    }
}

bool sukat_event_add(sukat_event_ctx_t *ctx, void *caller_ctx, int fd,
                     sukat_event_cb cb, uint32_t events)
{
  if (!ctx || fd < 0 || !cb)
    {
      ERR(ctx, "Faulty parameters to event add: ctx %p, fd %d, cb %p",
          ctx, fd, cb);
      return false;
    }
  else
    {
      struct ecall_ctx *call_ctx = calloc(1, sizeof(*call_ctx));
      struct epoll_event ev =
        {
          .events = events,
          .data.ptr = call_ctx
        };

      if (!call_ctx)
        {
          ERR(ctx, "OOM for call context: %s", strerror(errno));
          return false;
        }
      call_ctx->cb = cb;
      call_ctx->cb_ctx = caller_ctx;
      call_ctx->fd = fd;
      if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0)
        {
          ERR(ctx, "Failed to add fd %d event %x: %s", fd, events,
              strerror(errno));
          free(call_ctx);
          return false;
        }
      DBG(ctx, "Added event with fd %d, caller_ctx %p, cb %p, events %u",
          fd, caller_ctx, cb, events);
      ctx->n_fds++;
    }
  return true;
}

bool sukat_event_remove(sukat_event_ctx_t *ctx, int fd)
{
  if (!ctx || fd < 0)
    {
      ERR(ctx, "Invalid arguments. ctx %p, fd %d", ctx, fd);
      return false;
    }
  if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL) != 0)
    {
      ERR(ctx, "Failed to remove fd %d from events", fd);
      return false;
    }
  ctx->n_fds--;
  DBG(ctx, "Removed fd %d from epoll", fd);
  return true;
}

int sukat_event_read(sukat_event_ctx_t *ctx, int timeout)
{
  if (ctx)
    {
      const size_t n_events = (ctx->n_fds < 128) ? ctx->n_fds : 128;
      struct epoll_event events[n_events];
      int ret;

      ret = epoll_wait(ctx->epoll_fd, events, n_events, timeout);
      DBG(ctx, "Epoll returned %d", ret);
      if (ret > 0)
        {
          size_t n_events = (size_t)ret, i;

          for (i = 0; i < n_events; i++)
            {
              struct ecall_ctx *ecall = events[i].data.ptr;
              if (ecall->cb)
                {
                  ecall->cb(ecall->cb_ctx, ecall->fd, events[i].events);
                }
            }
        }
      else if (ret < 0)
        {
          ERR(ctx, "Epoll failed: %s", strerror(errno));
          return ret;
        }
    }
  else
    {
      ERR(ctx, "Invalid context");
      return -EINVAL;
    }
  return 0;
}

bool sukat_event_mod(sukat_event_ctx_t *ctx, void *caller_ctx, int fd,
                     sukat_event_cb cb, uint32_t events)
{
  if (sukat_event_remove(ctx, fd) == true)
    {
      // TODO: We dont want to actually just add a new, since then we have to
      // fiddle with the search tree two times. Modify existing, but no malloc
      // free pair.
      return sukat_event_add(ctx, caller_ctx, fd, cb, events);
    }
  return false;
}

/*! }@ */
