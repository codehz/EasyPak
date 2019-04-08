#pragma once

#include "ezpak.h"
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define checked_fdopendir(fd)                                                  \
  ({                                                                           \
    DIR *temp = fdopendir(fd);                                                 \
    if (temp == NULL) {                                                        \
      perror("opendir");                                                       \
      goto err;                                                                \
    };                                                                         \
    temp;                                                                      \
  })

#define checked_open(path, ...)                                                \
  ({                                                                           \
    int temp = open(path, ##__VA_ARGS__);                                      \
    if (temp == -1) {                                                          \
      perror("open");                                                          \
      goto err;                                                                \
    }                                                                          \
    temp;                                                                      \
  })

#define checked_openat(fd, path, oflag, ...)                                   \
  ({                                                                           \
    int temp = openat(fd, path, oflag, ##__VA_ARGS__);                         \
    if (temp == -1) {                                                          \
      perror("openat");                                                        \
      goto err;                                                                \
    }                                                                          \
    temp;                                                                      \
  })

#define checked_fstat(fd, buf)                                                 \
  ({                                                                           \
    if (fstat(fd, buf) != 0) {                                                 \
      perror("fstat");                                                         \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_readlinkat(fd, path, buf, bufsiz)                              \
  ({                                                                           \
    ssize_t temp = readlinkat(fd, path, buf, bufsiz);                          \
    if (temp == -1) {                                                          \
      perror("readlinkat");                                                    \
      goto err;                                                                \
    }                                                                          \
    temp;                                                                      \
  })

#define check_err(body)                                                        \
  if ((ret = body) != 0)                                                       \
    goto err;

#define PAD 2

char *readable_fs(double size);
char *printMode(uint16_t input);
EZ_RET pack_iterator(FILE *file, int dirfd, int level);
EZ_RET build_pack(FILE *output, FILE *input);