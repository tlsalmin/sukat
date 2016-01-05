#ifndef SUKAT_TEST_COMMON_H
#define SUKAT_TEST_COMMON_H
#include <iostream>
#include "sukat_log.h"

static inline void test_log_cb(enum sukat_log_lvl lvl, const char *msg)
{
  const bool enable_logging = false;
  const bool log_errors = true;

  if (enable_logging || (log_errors == true && lvl == SUKAT_LOG_ERROR))
    {
      std::cout << msg << std::endl;
    }
}
#endif
