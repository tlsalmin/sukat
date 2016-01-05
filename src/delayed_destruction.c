/*!
 * @file delayed_destruction.c
 * @brief Helper implementation for delayed free.
 *
 * @addtogroup delayed_destruction
 * @{
 */

#include <stdlib.h>
#include <assert.h>
#include "delayed_destruction.h"

struct destro_ctx
{
  struct destro_cbs cbs;
  void *caller_ctx;
  destro_client_t *deleted_head;
  destro_client_t *deleted_tail;
  struct
    {
      uint8_t in_callback:1;
      uint8_t destroyed:1;
      uint8_t unused:6;
    };
};

destro_t *destro_create(struct destro_params *params, struct destro_cbs *cbs)
{
  if (params)
    {
      destro_t *ctx = (destro_t *)calloc(1, sizeof(*ctx));
      if (ctx)
        {
          if (cbs)
            {
              memcpy(&ctx->cbs, cbs, sizeof(ctx->cbs));
            }
          ctx->caller_ctx = params->main_ctx;
          return ctx;
        }
    }
  return NULL;
}

static void destroy_main(destro_t *ctx)
{
  if (ctx->cbs.close)
    {
      ctx->cbs.close(ctx->caller_ctx, NULL);
    }
  if (ctx->cbs.dfree)
    {
      ctx->cbs.dfree(ctx->caller_ctx, NULL);
    }
  else
    {
      free(ctx->caller_ctx);
    }
  free(ctx);
}

static void destroy_client(destro_t *ctx, destro_client_t *client)
{
  if (ctx->cbs.close && !client->closed)
    {
      ctx->cbs.close(ctx->caller_ctx, (void *)client);
    }
  if (ctx->cbs.dfree)
    {
      ctx->cbs.dfree(ctx->caller_ctx, (void *)client);
    }
  else
    {
      free((void *)client);
    }
}

void destro_delete(destro_t *ctx, destro_client_t *client)
{
  if (!client)
    {
      ctx->destroyed = true;
      if (!ctx->in_callback)
        {
          DBG(ctx, "Destroying main directly");
          destroy_main(ctx);
        }
      else
        {
          DBG(ctx, "Adding main to delayed destruction");
          ctx->destroyed = true;
        }
    }
  else
    {
      client->destroyed = true;
      if (!ctx->in_callback)
        {
          DBG(ctx, "Destroying client %p directly", client);
          destroy_client(ctx, client);
        }
      else
        {
          DBG(ctx, "Adding %p to delayed removal", client);
          if (!ctx->deleted_tail)
            {
              assert(!ctx->deleted_head);
              ctx->deleted_head = ctx->deleted_tail = client;
            }
          else
            {
              ctx->deleted_tail->next = client;
              ctx->deleted_tail = client;
            }
          if (ctx->cbs.close && !client->closed)
            {
              ctx->cbs.close(ctx->caller_ctx, (void *)client);
            }
          client->closed = true;
        }
    }
}

void destro_cb_enter(destro_t *ctx)
{
  ctx->in_callback = true;
}

void destro_cb_exit(destro_t *ctx)
{
  ctx->in_callback = false;
  while (ctx->deleted_head)
    {
      destro_client_t *client = ctx->deleted_head;

      DBG(ctx, "Delayed removing %p", client);
      ctx->deleted_head = client->next;
      destroy_client(ctx, client);
    }
  ctx->deleted_head = ctx->deleted_tail = NULL;
  if (ctx->destroyed)
    {
      DBG(ctx, "Delayed destroying main context");
      destroy_main(ctx);
    }
}

bool destro_is_deleted(destro_t *ctx, destro_client_t *client)
{
  if (ctx->destroyed || (client && client->destroyed))
    {
      return true;
    }
  return false;
}

/*! @} */
