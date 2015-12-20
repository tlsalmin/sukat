/*!
 * @file sukat_log_internal.c
 * @brief Log functions.
 *
 * @addtogroup sukat_log
 * @{
 */

#include "sukat_log_internal.h"

void sukat_do_log(sukat_log_cb log_cb, enum sukat_log_lvl lvl, const char *func,
                  const size_t line, const char *fmt, ...)
{
  char log_msg[512];
  size_t used = 0;
  va_list ap;
#define LEFT (sizeof(log_msg) - used)
  if (log_cb)
    {

      used = snprintf(log_msg, LEFT, "%s():%zu ", func, line);
      va_start(ap, fmt);
      vsnprintf(log_msg + used, LEFT, fmt, ap);
      va_end(ap);

      log_cb(lvl, log_msg);
    }
#undef LEFT
}

/*! }@ */
