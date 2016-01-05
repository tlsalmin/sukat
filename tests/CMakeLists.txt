include_directories(${CMAKE_SOURCE_DIR}/src)
add_definitions(-std=c++11)

add_executable(test_tree test_sukat_tree.cpp)
add_executable(test_sock test_sukat_sock.cpp)
add_executable(test_bgp test_sukat_bgp.cpp)

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
  target_link_libraries(test_sock gcov)
  target_link_libraries(test_tree gcov)
  target_link_libraries(test_bgp gcov)
  setup_target_for_coverage(${PROJECT_NAME}_tree_coverage test_tree coverage)
  setup_target_for_coverage(${PROJECT_NAME}_sock_coverage test_sock coverage)
  setup_target_for_coverage(${PROJECT_NAME}_bgp_coverage test_bgp coverage)
endif()

target_link_libraries(test_sock gtest gtest_main)
target_link_libraries(test_tree gtest gtest_main)
target_link_libraries(test_bgp gtest gtest_main)
target_link_libraries(test_tree sukat)
target_link_libraries(test_sock sukat)
target_link_libraries(test_bgp sukat)
add_test(NAME TEST-TREE COMMAND test_tree)
add_test(NAME TEST-SOCK COMMAND test_sock)
add_test(NAME TEST-BGP COMMAND test_bgp)
