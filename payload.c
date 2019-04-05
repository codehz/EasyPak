#include "payload.h"
#include <elf.h>

#if defined(__LP64__)
#define XELF Elf64_Ehdr
#else
#define XELF Elf32_Ehdr
#endif

#define checked_fopen(path, ...)                                               \
  ({                                                                           \
    FILE *temp = fopen(path, ##__VA_ARGS__);                                   \
    if (temp == NULL) {                                                        \
      perror("fopen");                                                         \
      goto err;                                                                \
    }                                                                          \
    temp;                                                                      \
  })

#define checked_read(ptr, size, stream)                                        \
  ({                                                                           \
    int ret = fread(ptr, size, 1, stream);                                     \
    if (ret != 1) {                                                            \
      perror("fread");                                                         \
      goto err;                                                                \
    }                                                                          \
    ret;                                                                       \
  })

FILE *getpayload(size_t *size) {
  FILE *file = NULL;
  XELF ehdr;
  file = checked_fopen("/proc/self/exe", "r");
  checked_read(&ehdr, sizeof(ehdr), file);
  int pos = ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize;
  fseek(file, pos, SEEK_SET);
  if (size) {
    checked_read(&ehdr, sizeof(ehdr), file);
    *size = ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize;
    fseek(file, pos, SEEK_SET);
  }
  return file;
err:
  if (file)
    fclose(file);
  return NULL;
}