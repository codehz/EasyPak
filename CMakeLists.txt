cmake_minimum_required(VERSION 3.13)

add_library(ezpak ezpak.c ezpak.h)

add_executable(ezio ezio.c)
target_link_libraries(ezio ezpak)

add_executable(stub stub.c)
target_link_libraries(stub ezpak)

install(TARGETS ezio RUNTIME DESTINATION bin)
