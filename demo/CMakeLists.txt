add_executable(bgp_query bgp_query.c)
include_directories(${CMAKE_SOURCE_DIR}/include)
target_link_libraries(bgp_query sukat)
