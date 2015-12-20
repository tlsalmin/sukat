cmake_minimum_required(VERSION 3.1)
project(sukat)

add_subdirectory(src)
include_directories(include)

set (SUKAT_LIBS ${SUKAT_LIBS} sukat)
option(test "Build all tests." OFF)
if (test)
  enable_testing()
  add_subdirectory(tests)
endif()
