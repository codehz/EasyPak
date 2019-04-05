cmake_minimum_required(VERSION 3.13)

SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
SET(BUILD_SHARED_LIBS OFF)
SET(CMAKE_EXE_LINKER_FLAGS "-static")

add_library(ezpak ezpak.c ezpak.h)
add_library(payload payload.c payload.h)

add_executable(ezio ezio.c)
target_link_libraries(ezio ezpak)

add_executable(stub stub.c parse_arg.c)
target_link_libraries(stub ezpak payload)

add_executable(ezbin-zero ezbin.c)
target_link_libraries(ezbin-zero ezpak payload)

add_custom_command(
  OUTPUT ezbin
  POST_BUILD
  COMMAND cat ezbin-zero stub > ezbin
  COMMAND chmod +x ezbin
  MAIN_DEPENDENCY ezbin-zero
  DEPENDS stub
  COMMENT "Embedding stub to ezbin")

add_custom_target(ez ALL DEPENDS ezbin)

install(TARGETS ezio RUNTIME DESTINATION bin)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/ezbin DESTINATION bin)