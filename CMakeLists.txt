cmake_minimum_required(VERSION 3.1)
project(sukat)

add_subdirectory(src)
include_directories(include)

add_subdirectory(tools)

set (SUKAT_LIBS ${SUKAT_LIBS} sukat)
option(test "Build all tests." OFF)
if (test)
  enable_testing()
  add_subdirectory(tests)
endif()

find_package(Doxygen)
if (DOXYGEN_FOUND)
  # Grabbed from
  # https://majewsky.wordpress.com/2010/08/14/tip-of-the-day-cmake-and-doxygen/
  set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
  set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

  configure_file(${doxyfile_in} ${doxyfile} @ONLY)
  add_custom_target(doc
    ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif()
