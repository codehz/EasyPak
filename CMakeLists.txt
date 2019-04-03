add_library(ezpak ezpak.c ezpak.h)

add_executable(ezio ezio.c)

target_link_libraries(ezio ezpak)