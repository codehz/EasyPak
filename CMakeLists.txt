cmake_minimum_required(VERSION 3.13)

SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
SET(BUILD_SHARED_LIBS OFF)
SET(CMAKE_EXE_LINKER_FLAGS "-static")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-switch -Wno-unused-command-line-argument")

include(ExternalProject)

ExternalProject_Add(
  libfuse
  PREFIX libfuse
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libfuse
  CONFIGURE_COMMAND CC=${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/build-libfuse.sh ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
  BUILD_COMMAND ninja
  INSTALL_COMMAND ninja install
)

ExternalProject_Get_property(libfuse INSTALL_DIR)
set(FUSE_DIR ${INSTALL_DIR})
unset(INSTALL_DIR)

add_library(ezpak ezpak.c ezpak.h)
add_library(payload payload.c payload.h)

add_executable(ezio ezio.c)
target_link_libraries(ezio ezpak)

add_library(fuse_support fuse_support.c fuse_support.h)
add_dependencies(fuse_support libfuse)
target_link_directories(fuse_support INTERFACE ${FUSE_DIR}/lib)
target_link_libraries(fuse_support INTERFACE fuse3)
target_include_directories(fuse_support PRIVATE ${FUSE_DIR}/include)

add_executable(stub stub.c parse_arg.c envsolver.c)
target_link_libraries(stub ezpak payload fuse_support)

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

set_property(SOURCE ezbin-zero PROPERTY GENERATED 1)

add_custom_target(ez ALL DEPENDS ezbin)

install(TARGETS ezio RUNTIME DESTINATION bin)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/ezbin DESTINATION bin)