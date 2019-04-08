#define _GNU_SOURCE

#include "ezpak.h"
#include "ezutils.h"
#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#define checked_fopen(path, ...)                                               \
  ({                                                                           \
    FILE *temp = fopen(path, ##__VA_ARGS__);                                   \
    if (temp == NULL) {                                                        \
      perror("fopen");                                                         \
      goto err;                                                                \
    }                                                                          \
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

#define checked_fchmod(fd, mode)                                               \
  ({                                                                           \
    if (fchmod(fd, mode) != 0) {                                               \
      perror("fchmod");                                                        \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_mkdir(path, mode)                                              \
  ({                                                                           \
    if (mkdir(path, mode) != 0) {                                              \
      perror("mkdir");                                                         \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_mkdirat(fd, path, mode)                                        \
  ({                                                                           \
    if (mkdirat(fd, path, mode) != 0) {                                        \
      perror("mkdir");                                                         \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_symlinkat(...)                                                 \
  ({                                                                           \
    if (symlinkat(__VA_ARGS__) != 0) {                                         \
      perror("symlink");                                                       \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_sendfile(out_fd, in_fd, offset, count)                         \
  ({                                                                           \
    ssize_t ret = sendfile(out_fd, in_fd, offset, count);                      \
    if (ret == -1) {                                                           \
      perror("sendfile");                                                      \
      return EZ_ERROR_SYSCALL;                                                 \
    }                                                                          \
    ret;                                                                       \
  })

typedef struct fd_chain {
  int fd;
  uint16_t mode;
  struct fd_chain *last;
} fd_chain;

fd_chain *mkfd_chain(int fd) {
  fd_chain *ret = malloc(sizeof(fd_chain));
  ret->fd = fd;
  ret->mode = 0755;
  ret->last = NULL;
  return ret;
}

fd_chain *fd_push(fd_chain *chain, char const *dir, uint16_t mode) {
  int nfd = checked_openat(chain->fd, dir, O_DIRECTORY);
  fd_chain *ret = malloc(sizeof(fd_chain));
  ret->fd = nfd;
  ret->mode = mode;
  ret->last = chain;
  return ret;
err:
  return NULL;
}

fd_chain *fd_pop(fd_chain *chain) {
  checked_fchmod(chain->fd, chain->mode);
  close(chain->fd);
  fd_chain *last = chain->last;
  free(chain);
  return last;
err:
  return NULL;
}

int fd_chain_pad(fd_chain *chain) {
  int len = 0;
  while (chain->last) {
    len++;
    chain = chain->last;
  }
  return len * PAD;
}

void fd_chain_free(fd_chain *chain) {
  if (chain == NULL)
    return;
  close(chain->fd);
  fd_chain_free(chain->last);
}

EZ_RET my_callback_v(void *user, EZ_TYPE type, va_list list) {
  fd_chain **pchain = user, *chain = *pchain;
  int fd = -1;
  switch (type) {
  case EZ_T_MAN: {
    char const *key = va_arg(list, char const *);
    char const *val = va_arg(list, char const *);
    printf("m--------- %*s%s: %s\n", fd_chain_pad(chain), "", key, val);
    break;
  }
  case EZ_T_REG: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    char const *content = va_arg(list, char const *);
    uint64_t size = va_arg(list, uint64_t);
    printf("-%s %*s%s (%s)\n", printMode(mode), fd_chain_pad(chain), "", key,
           readable_fs(size));
    fd = checked_openat(chain->fd, key, O_WRONLY);
    write(fd, content, size);
    close(fd);
    fd = -1;
    break;
  }
  case EZ_T_SENDFILE: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    int sfd = va_arg(list, int);
    off_t *off = va_arg(list, off_t *);
    size_t size = va_arg(list, size_t);
    printf("-%s %*s%s (%s)\n", printMode(mode), fd_chain_pad(chain), "", key,
           readable_fs(size));
    fd = checked_openat(chain->fd, key, O_WRONLY | O_CREAT, 0777);
    checked_sendfile(fd, sfd, off, size);
    checked_fchmod(fd, mode);
    close(fd);
    fd = -1;
    break;
  }
  case EZ_T_LNK: {
    char const *key = va_arg(list, char const *);
    char const *val = va_arg(list, char const *);
    printf("lrwxrwxrwx %*s%s -> %s\n", fd_chain_pad(chain), "", key, val);
    checked_symlinkat(val, chain->fd, key);
    break;
  }
  case EZ_T_DIR: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    printf("d%s %*s%s\n", printMode(mode), fd_chain_pad(chain), "", key);
    checked_mkdirat(chain->fd, key, 0777);
    fd_chain *n = fd_push(chain, key, mode);
    if (!n)
      goto err;
    *pchain = n;
    break;
  }
  case EZ_T_POP: {
    fd_chain *n = fd_pop(chain);
    if (!n)
      goto corrupt;
    *pchain = n;
    break;
  }
  case EZ_T_END:
    break;
  default:
    return EZ_ERROR_NOT_IMPL;
  }
  return EZ_OK;
err:
  if (fd == -1)
    close(fd);
  return EZ_ERROR_SYSCALL;
corrupt:
  return EZ_ERROR_CORRUPT;
}

EZ_RET my_callback(void *user, EZ_TYPE type, ...) {
  va_list list;
  va_start(list, type);
  EZ_RET ret = my_callback_v(user, type, list);
  va_end(list);
  return ret;
}

EZ_RET list_callback_v(void *user, EZ_TYPE type, va_list list) {
  int *level = user;
  switch (type) {
  case EZ_T_MAN: {
    char const *key = va_arg(list, char const *);
    char const *val = va_arg(list, char const *);
    printf("m--------- %*s%s: %s\n", *level * PAD, "", key, val);
    break;
  }
  case EZ_T_REG: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    char const *content = va_arg(list, char const *);
    (void)content;
    uint64_t size = va_arg(list, uint64_t);
    printf("-%s %*s%s (%s)\n", printMode(mode), *level * PAD, "", key,
           readable_fs(size));
    break;
  }
  case EZ_T_SENDFILE: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    int sfd = va_arg(list, int);
    off_t *off = va_arg(list, off_t *);
    size_t size = va_arg(list, size_t);
    (void)sfd;
    (void)off;
    printf("-%s %*s%s (%s)\n", printMode(mode), *level * PAD, "", key,
           readable_fs(size));
    break;
  }
  case EZ_T_LNK: {
    char const *key = va_arg(list, char const *);
    char const *val = va_arg(list, char const *);
    printf("lrwxrwxrwx %*s%s -> %s\n", *level * PAD, "", key, val);
    break;
  }
  case EZ_T_DIR: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    printf("d%s %*s%s\n", printMode(mode), *level * PAD, "", key);
    (*level)++;
    break;
  }
  case EZ_T_POP:
    (*level)--;
    break;
  case EZ_T_END:
    break;
  default:
    return EZ_ERROR_NOT_IMPL;
  }
  return EZ_OK;
}

EZ_RET list_callback(void *user, EZ_TYPE type, ...) {
  va_list list;
  va_start(list, type);
  EZ_RET ret = list_callback_v(user, type, list);
  va_end(list);
  return ret;
}

int main(int argc, char *argv[]) {
  FILE *arch = NULL, *output = NULL, *input = NULL;
  fd_chain *chain = NULL;
  EZ_RET ret = EZ_OK;
  if (argc <= 2)
    goto err_args;
  if (strcmp(argv[1], "pack") == 0) {
    if (argc != 4)
      goto err_args;
    arch = checked_fopen(argv[2], "wb");
    int dir = checked_open(argv[3], O_DIRECTORY);
    check_err(ez_begin(arch));
    check_err(pack_iterator(arch, dir, 0));
    check_err(ez_end(arch));
    fclose(arch);
  } else if (strcmp(argv[1], "unpack") == 0) {
    if (argc != 4)
      goto err_args;
    arch = checked_fopen(argv[2], "rb");
    checked_mkdir(argv[3], 0755);
    int dir = checked_open(argv[3], O_DIRECTORY);
    chain = mkfd_chain(dir);
    check_err(ez_unpack(arch, true, my_callback, &chain));
    fd_chain_free(chain);
  } else if (strcmp(argv[1], "test") == 0) {
    if (argc != 3)
      goto err_args;
    arch = checked_fopen(argv[2], "rb");
    int level = 0;
    check_err(ez_unpack(arch, true, list_callback, &level));
  } else if (strcmp(argv[1], "build") == 0) {
    output = checked_fopen(argv[2], "wb");
    input = checked_fopen(argv[3], "rb");
    check_err(ez_begin(output));
    check_err(build_pack(output, input));
    check_err(ez_end(output));
    fclose(output);
    fclose(input);
    output = NULL;
    input = NULL;
  } else
    goto err_args;
  return 0;

err_args:
  errx(1, "%s (pack|unpack|test|build) pack dir", argv[0]);

err:
  fd_chain_free(chain);
  if (arch)
    fclose(arch);
  if (output)
    fclose(output);
  if (input)
    fclose(input);
  fprintf(stderr, "%s\n", ez_error_string(ret));
  return ret ?: -1;
}