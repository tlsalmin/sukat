add_library(sukat sukat_sock.c sukat_event.c tree_avl.c tree_binary.c
  sukat_drawer.c sukat_bgp.c delayed_destruction.c sukat_log_internal.c
  sukat_util.c)
include_directories(${CMAKE_SOURCE_DIR}/include)

target_include_directories (sukat PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
