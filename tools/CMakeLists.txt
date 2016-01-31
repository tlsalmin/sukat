add_executable(bgp_query bgp_query.c tools_common.c)
include_directories(${CMAKE_SOURCE_DIR}/include)
target_link_libraries(bgp_query sukat)

add_executable(netdoge netdoge.c tools_common.c)
target_link_libraries(netdoge sukat)
