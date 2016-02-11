include_directories(${CMAKE_SOURCE_DIR}/include)
add_definitions(-std=c++11)

set(list_of_benchmarks "sock")

foreach(bm_var ${list_of_benchmarks})
  add_executable(benchmark_${bm_var} benchmark_${bm_var}.cpp)
  target_link_libraries(benchmark_${bm_var} sukat)
  target_link_libraries(benchmark_${bm_var} benchmark)
  target_link_libraries(benchmark_${bm_var} pthread)
endforeach()
