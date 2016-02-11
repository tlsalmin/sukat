/*!
 * @file sukat_log_internal.h
 * @brief Internal log macroes.
 *
 * @addtogroup sukat_log
 * @{
 */

#ifndef SUKAT_LOG_INTERNAL_H
#define SUKAT_LOG_INTERNAL_H

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "sukat_log.h"

void sukat_do_log(sukat_log_cb log_cb, enum sukat_log_lvl lvl, const char *func,
                  const size_t line, const char *fmt, ...);

#define LOG_CB(_ctx) ((_ctx) ? _ctx->cbs.log_cb : NULL)
#define ERR(_ctx, ...) \
  sukat_do_log(LOG_CB(_ctx), SUKAT_LOG_ERROR, __func__, __LINE__, __VA_ARGS__)
#define LOG(_ctx, ...) \
  sukat_do_log(LOG_CB(_ctx), SUKAT_LOG, __func__, __LINE__, __VA_ARGS__)
#ifndef NDEBUG
#define DBG_DEF(...) __VA_ARGS__
#define DBG(_ctx, ...) \
  sukat_do_log(LOG_CB(_ctx), SUKAT_LOG_DBG, __func__, __LINE__, __VA_ARGS__)
#else /* NDEBUG */
#define DBG(...)
#define DBG_DEF(...)
#endif

//! In time of need, just initialize a dummy struct for using these macroes.
struct dummy_cbs
{
  sukat_log_cb log_cb;
};

struct dummy_ctx
{
  struct dummy_cbs cbs;
};


#endif /* !SUKAT_LOG_INTERNAL_H */

/*! }@ */
