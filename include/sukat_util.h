/*!
 * @file sukat_util.h
 * @brief Random utility functions
 *
 * @defgroup sukat_util
 * @ingroup sukat_api
 * @{
 *
 */

#ifndef SUKAT_UTIL_H
#define SUKAT_UTIL_H

#include <getopt.h>
#include <stdio.h>

/*!
 * @brief Formats the \p opts with \p explanations to a usage string.
 *
 * The parsing is stopped when opts[i].name is null (which is kinda the
 * same behaviour getopt_long uses anyway). Just make sure explanations
 * cover each part (with e.g. a static assert).
 *
 * @param opts          Array of options.
 * @param explanations  Array of explanations matching options.
 * @param output        Output file.
 */
void sukat_util_usage(const struct option *opts, const char **explanations,
                      FILE *output);

#endif /* SUKAT_UTIL_H */

/*! @} */
