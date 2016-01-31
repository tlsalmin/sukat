#ifndef TOOLS_COMMON_H
#define TOOLS_COMMON_H

#include <stdbool.h>

extern bool keep_running;

/*!
 * @brief Register a sighandler that will set ::keep_running to false on SIGINT
 *
 * @return true  Success
 * @return false Failure
 */
bool simple_sighandler();

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
unsigned long long safe_unsigned(char *value_in_ascii, long long int max_size);

#endif /* !TOOLS_COMMON_H */
