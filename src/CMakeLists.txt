add_library(sukat sukat_sock.c sukat_event.c tree_avl.c tree_binary.c
  sukat_drawer.c)
include_directories(${CMAKE_SOURCE_DIR}/include)

target_include_directories (sukat PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
