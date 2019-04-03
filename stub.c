#define _GNU_SOURCE

#include "ezpak.h"
#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wordexp.h>

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

#define checked_open(path, ...)                                                \
  ({                                                                           \
    int fd = open(path, ##__VA_ARGS__);                                        \
    if (fd == -1) {                                                            \
      perror("open");                                                          \
      goto err;                                                                \
    }                                                                          \
    fd;                                                                        \
  })

#define checked_read(ptr, size, stream)                                        \
  ({                                                                           \
    int ret = fread(ptr, size, 1, stream);                                     \
    if (ret != 1) {                                                            \
      perror("fread");                                                         \
      return EZ_ERROR_SYSCALL;                                                 \
    }                                                                          \
    ret;                                                                       \
  })

#define checked_fputs(str, stream)                                             \
  ({                                                                           \
    int ret = fputs(str, stream);                                              \
    if (ret < 0) {                                                             \
      perror("fputs");                                                         \
      return EZ_ERROR_SYSCALL;                                                 \
    }                                                                          \
    ret;                                                                       \
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

#define checked_fchmod(fd, mode)                                               \
  ({                                                                           \
    if (fchmod(fd, mode) != 0) {                                               \
      perror("fchmod");                                                        \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_symlink(...)                                                   \
  ({                                                                           \
    if (symlink(__VA_ARGS__) != 0) {                                           \
      perror("symlink");                                                       \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_mount(...)                                                     \
  ({                                                                           \
    if (mount(__VA_ARGS__) != 0) {                                             \
      perror("mount");                                                         \
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

#define checked_chdir(path)                                                    \
  ({                                                                           \
    if (chdir(path) != 0) {                                                    \
      perror("chdir");                                                         \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_unshare(flags)                                                 \
  ({                                                                           \
    if (unshare(flags) != 0) {                                                 \
      perror("unshare");                                                       \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_wordexp(s, p, flags)                                           \
  ({                                                                           \
    if (wordexp(s, p, flags) != 0) {                                           \
      perror("wordexp");                                                       \
      goto err;                                                                \
    }                                                                          \
  })

#define check_err(body)                                                        \
  if ((ret = body) != 0)                                                       \
    goto err;

typedef enum pkstrategy {
  STRATEGY_ERROR,
  STRATEGY_OVERWRITE,
  STRATEGY_SKIP
} pkstrategy;

typedef struct pkstatus {
  pkstrategy overwrite_folder;
  pkstrategy overwrite_file;
} pkstatus;

#define STREQ(a, b) (strcmp(a, b) == 0)

EZ_RET deny_to_setgroups() {
  FILE *file = NULL;
  file = checked_fopen("/proc/self/setgroups", "w");
  checked_fputs("deny", file);
  fclose(file);
  return EZ_OK;
err:
  if (file)
    fclose(file);
  return EZ_ERROR_SYSCALL;
}

EZ_RET map_to_root(int id, char const *filename) {
  FILE *file = NULL;
  file = checked_fopen(filename, "w");
  if (fprintf(file, "0 %d 1", id) != 1) {
    perror("fprintf");
    goto err;
  }
  fclose(file);
  return EZ_OK;
err:
  if (file)
    fclose(file);
  return EZ_ERROR_SYSCALL;
}

static char **g_argv;

EZ_RET list_callback_v(void *user, EZ_TYPE type, va_list list) {
  pkstatus *status = user;
  char *buffer = NULL;
  wordexp_t exp = {0};
  int fd = -1;
  switch (type) {
  case EZ_T_MAN: {
    char const *key = va_arg(list, char const *);
    char const *val = va_arg(list, char const *);
    if (STREQ(key, "print")) {
      printf("%s\n", val);
    } else if (STREQ(key, "warn")) {
      fprintf(stderr, "%s\n", val);
    } else if (STREQ(key, "strategy")) {
      int mode = 0;
      if (sscanf(val, "overwrite_folder:%d", &mode) != 1) {
        if (mode < STRATEGY_ERROR || mode > STRATEGY_SKIP)
          return EZ_ERROR_CORRUPT;
        status->overwrite_folder = mode;
      } else if (sscanf(val, "overwrite_file:%d", &mode) != 1) {
        if (mode < STRATEGY_ERROR || mode > STRATEGY_SKIP)
          return EZ_ERROR_CORRUPT;
        status->overwrite_file = mode;
      } else {
        fprintf(stderr, "unsupported strategy: %s\n", val);
      }
    } else if (STREQ(key, "chdir")) {
      if (val[0] == '~' && (val[1] == '/' || val[1] == 0)) {
        asprintf(&buffer, "%s%s", getenv("HOME"), val + 1);
        checked_chdir(buffer);
        free(buffer);
      } else {
        checked_chdir(val);
      }
    } else if (STREQ(key, "bind")) {
      char from[FILENAME_MAX], to[FILENAME_MAX];
      if (sscanf(val, "%[^:]:%[^:]", from, to) == 2) {
        checked_mount(from, to, "tmpfs", MS_BIND | MS_REC, NULL);
      } else {
        fprintf(stderr, "wrong format to mount");
        return EZ_ERROR_CORRUPT;
      }
    } else if (STREQ(key, "exec")) {
      checked_wordexp(val, &exp, 0);
      execv(exp.we_wordv[0], exp.we_wordv);
      perror("execv");
      exit(254);
    } else if (STREQ(key, "exec-passthru")) {
      execv(val, g_argv);
      perror("execv");
      exit(254);
    }
    break;
  }
  case EZ_T_REG: {
    assert(false);
    break;
  }
  case EZ_T_SENDFILE: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    int sfd = va_arg(list, int);
    off_t *off = va_arg(list, off_t *);
    size_t size = va_arg(list, size_t);
    fd = checked_open(key, O_WRONLY | O_CREAT, 0777);
    checked_sendfile(fd, sfd, off, size);
    checked_fchmod(fd, mode);
    close(fd);
    fd = -1;
    break;
  }
  case EZ_T_LNK: {
    char const *key = va_arg(list, char const *);
    char const *val = va_arg(list, char const *);
    checked_symlink(val, key);
    break;
  }
  case EZ_T_DIR: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    checked_mkdir(key, mode);
    checked_chdir(key);
    break;
  }
  case EZ_T_POP:
    checked_chdir("..");
    break;
  case EZ_T_END:
    break;
  default:
    return EZ_ERROR_NOT_IMPL;
  }
  return EZ_OK;
err:
  wordfree(&exp);
  free(buffer);
  if (fd != -1)
    close(fd);
  return EZ_ERROR_SYSCALL;
}

EZ_RET list_callback(void *user, EZ_TYPE type, ...) {
  va_list list;
  va_start(list, type);
  EZ_RET ret = list_callback_v(user, type, list);
  va_end(list);
  return ret;
}

int main(int argc, char *argv[]) {
  g_argv = argv;
  FILE *file;
  XELF ehdr;
  EZ_RET ret;
  size_t elfsize = 0;
  file = checked_fopen("/proc/self/exe", "r");
  checked_read(&ehdr, sizeof(ehdr), file);
  elfsize = ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize;
  fseek(file, elfsize, SEEK_SET);
  if (getuid() != 0) {
    checked_unshare(CLONE_NEWUSER);
    deny_to_setgroups();
    map_to_root(geteuid(), "/proc/self/uid_map");
    map_to_root(getegid(), "/proc/self/gid_map");
  }
  checked_unshare(CLONE_NEWNS);
  // check_err(ez_unpack(file, true, ez_callback callback, NULL));
  return 0;
err:
  return 1;
}