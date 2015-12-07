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
#define DBG(_ctx, ...) \
  sukat_do_log(LOG_CB(_ctx), SUKAT_LOG_DBG, __func__, __LINE__, __VA_ARGS__)
