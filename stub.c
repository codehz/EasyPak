#include "ezpak.h"
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#if defined(__LP64__)
#define XELF Elf64_Ehdr
#else
#define XELF Elf32_Ehdr
#endif

#define checked_read(fd, buf, size)                                            \
  ({                                                                           \
    if (size != read(fd, buf, size)) {                                         \
      perror("read");                                                          \
      goto err;                                                                \
    }                                                                          \
  })

#define std_checked(func, ...)                                                 \
  ({                                                                           \
    int temp = func(__VA_ARGS__);                                              \
    if (temp == -1) {                                                          \
      perror(#func);                                                           \
      goto err;                                                                \
    }                                                                          \
    temp;                                                                      \
  })

int main(int argc, char *argv[]) {
  int fd = -1;
  XELF ehdr;
  size_t elfsize = 0;
  fd = std_checked(open, "/proc/self/exe", O_RDONLY, 0);
  checked_read(fd, &ehdr, sizeof(ehdr));
  elfsize = ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize;
  std_checked(lseek, fd, elfsize, SEEK_SET);
  return 0;
err:
  return 1;
}