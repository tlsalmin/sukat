add_library(libsukat sukat_sock.c sukat_event.c sukat_tree.c tree_binary.c
  sukat_drawer.c)
include_directories(${CMAKE_SOURCE_DIR}/include)

target_include_directories (libsukat PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
