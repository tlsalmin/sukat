/*!
 * @file sukat_util.h
 * @brief Random utility functions
 *
 * @defgroup sukat_util
 * @ingroup sukat_api
 * @{
 *
 */

#pragma once

#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

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

/*!
 * @brief Set flags O_NONBLOCK and FD_CLOEXEC on the fd.
 *
 * @param fd    FD to modify.
 *
 * @return 0    Success.
 * @return < 0  Error.
 */
int sukat_util_flagit(int fd);

/*! @brief Types of input range. */
enum sukat_util_range_input_type
{
  SUKAT_UTIL_RANGE_INPUT_INTEGER, //!< Regular integer.
  SUKAT_UTIL_RANGE_INPUT_IP, //!< IPv4 or IPv6.
};

/*! @brief Types of values. */
enum sukat_util_range_value_type
{
  SUKAT_UTIL_RANGE_VALUE_4BYTE, //!< E.g. uint32.t
  SUKAT_UTIL_RANGE_VALUE_16BYTE, //!< e.g __int128.
};

/*! @brief Storage for range conversion result */
struct sukat_util_range_values
{
  enum sukat_util_range_value_type type; //!< Type stored.
  //!< Start, end and count of results. All values are in host-byte order.
  union
    {
      uint32_t start4;
      __int128 start16;
    };
  union
    {
      uint32_t end4;
      __int128 end16;
    };
  union
    {
      uint32_t count4;
      __int128 count16;
    };
};

/*!
 * @brief Convert a range (two values separated by a dash) to integers.
 *
 * if no dash is present, start == end and count == 1.
 *
 * @param range Range string to convert.
 * @param type Type expected of range.
 * @param values Place to store values.
 *
 * @return == true Success.
 * @return == false Failure.
 */
bool sukat_util_range_to_integers(const char *range,
                                  enum sukat_util_range_input_type type,
                                  struct sukat_util_range_values *values);

/** @brief Host to network for 128-bit integers */
__int128 sukat_util_ntohlll(__int128 orig);

/**
 * @brief Increse file descriptor limit.
 *
 * @param minimum Minimum to increase. The default increase is double the
 *                 minimum
 *
 * @return true Success.
 * @return false Failure.
 */
bool sukat_util_file_limit_increase(const unsigned int minimum);

/*! @} */
