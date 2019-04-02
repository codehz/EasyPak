add_library(ezpak ezpak.c ezpak.h)

add_executable(test test.c)

target_link_libraries(test ezpak)