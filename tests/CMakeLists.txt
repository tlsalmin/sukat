include_directories(${CMAKE_SOURCE_DIR}/src)
add_definitions(-std=c++11)

set(list_of_tests "tree" "sock" "bgp" "destro")

foreach(test_var ${list_of_tests})
  add_executable(test_${test_var} test_sukat_${test_var}.cpp)
endforeach()

option(coverage "Calculate test coverage." OFF)
if (coverage)
  # Grabbed from
  # http://stackoverflow.com/questions/13116488/detailed-guide-on-using-gcov-with-cmake-cdash
  set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)
  include(CodeCoverage)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fprofile-arcs -ftest-coverage")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fprofile-arcs -ftest-coverage")
  set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")
  foreach(test_var ${list_of_tests})
    target_link_libraries(test_${test_var} gcov)
    setup_target_for_coverage(${PROJECT_NAME}_${test_var}_coverage test_${test_var} coverage)
  endforeach()
endif()

foreach(test_var ${list_of_tests})
  target_link_libraries(test_${test_var} gtest gtest_main)
  target_link_libraries(test_${test_var} sukat)
  add_test(NAME TEST-${test_var} COMMAND test_${test_var})
endforeach()
