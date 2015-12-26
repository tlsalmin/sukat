#ifndef SUKAT_TEST_COMMON_H
#define SUKAT_TEST_COMMON_H
#include <iostream>
#include "sukat_log.h"

static inline void test_log_cb(enum sukat_log_lvl, const char *msg)
{
  const bool enable_logging = false;

  if (enable_logging)
    {
      std::cout << msg << std::endl;
    }
}
#endif
