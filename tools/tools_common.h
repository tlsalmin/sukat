#pragma once

#include <stdbool.h>
#include <sys/signalfd.h>

/*!
 * @brief Creates a signalfd for termination/interruption.
 *
 * @param additional_signals Additional signals to register.
 *
 * @return >= 0         signalfd.
 * @return <  0         Failure.
 */
int simple_sighandler(const sigset_t *additional_signals);

/*!
 * @brief Reads the signalfd for a signal.
 *
 * @param sigfd Signalfd to read.
 *
 * @return      >    0  Signal read.
 * @return      ==   0  No signal received.
 * @return      <    0  Failure.
 */
int simple_sighandler_read_signal(int sigfd);

/*!
 * @brief Parse \p value_in_ascii and check that its not larget than \p max_size.
 *
 * Exits on failure.
 *
 * @param value_in_ascii        Value as string.
 * @param max_size              Maximum value allowed.
 *
 * @return value parsed
 */
unsigned long long safe_unsigned(const char *value_in_ascii,
                                 long long int max_size);
