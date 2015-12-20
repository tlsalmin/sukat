/*!
 * @file sukat_log.h
 * @brief Log functionality for the sukat toolkit.
 *
 * @defgroup sukat_log
 * @ingroup sukat_api
 * @{
 */

#ifndef SUKAT_LOG_H
#define SUKAT_LOG_H

enum sukat_log_lvl
{
  SUKAT_LOG_ERROR,
  SUKAT_LOG,
  SUKAT_LOG_DBG,
};

/*!
 * Callback invoked for log messages created by the library
 *
 * @param lvl Log level.
 * @param msg Message containing function and line.
 */
typedef void (*sukat_log_cb)(enum sukat_log_lvl lvl, const char *msg);

#endif /* SUKAT_LOG_H */

/*! }@ */
