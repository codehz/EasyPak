#define _GNU_SOURCE

#include "ezpak.h"
#include "parse_arg.h"
#include "payload.h"
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define pivot_root(new_root, put_old) syscall(SYS_pivot_root, new_root, put_old)

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

#define checked_write(fd, buf, count)                                          \
  ({                                                                           \
    int ret = write(fd, buf, count);                                           \
    if (ret == -1) {                                                           \
      perror("write");                                                         \
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

#define checked_chroot(path)                                                   \
  ({                                                                           \
    if (chroot(path) != 0) {                                                   \
      perror("chroot");                                                        \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_pivot_root(new_root, putold)                                   \
  ({                                                                           \
    if (pivot_root(new_root, putold) != 0) {                                   \
      perror("pivot_root");                                                    \
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
  pkstrategy overwrite;
} pkstatus;

#define STREQ(a, b) (strcmp(a, b) == 0)

EZ_RET deny_to_setgroups() {
  int fd = -1;
  fd = checked_open("/proc/self/setgroups", O_WRONLY);
  checked_write(fd, "deny", 4);
  close(fd);
  return EZ_OK;
err:
  if (fd != -1)
    close(fd);
  return EZ_ERROR_SYSCALL;
}

EZ_RET map_to_root(int id, char const *filename) {
  int fd = -1;
  char temp[256];
  snprintf(temp, 256, "0 %d 1", id);
  fd = checked_open(filename, O_WRONLY);
  if (write(fd, temp, strlen(temp)) < 0) {
    perror("write");
    goto err;
  }
  close(fd);
  return EZ_OK;
err:
  if (fd != -1)
    close(fd);
  return EZ_ERROR_SYSCALL;
}

static void mkdir_p(const char *dir) {
  char tmp[FILENAME_MAX];
  char *p = NULL;
  size_t len;

  snprintf(tmp, sizeof(tmp), "%s", dir);
  len = strlen(tmp);
  if (tmp[len - 1] == '/')
    tmp[len - 1] = 0;
  for (p = tmp + 1; *p; p++)
    if (*p == '/') {
      *p = 0;
      mkdir(tmp, 0755);
      *p = '/';
    }
  mkdir(tmp, 0755);
}

static char **g_argv;

EZ_RET my_callback_v(void *user, EZ_TYPE type, va_list list) {
  pkstatus *status = user;
  char *buffer = NULL;
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
      if (sscanf(val, "overwrite:%d", &mode) != 1) {
        if (mode < STRATEGY_ERROR || mode > STRATEGY_SKIP)
          return EZ_ERROR_CORRUPT;
        status->overwrite = mode;
      } else {
        fprintf(stderr, "unsupported strategy: %s\n", val);
        return EZ_ERROR_CORRUPT;
      }
    } else if (STREQ(key, "chdir")) {
      mkdir_p(val);
      checked_chdir(val);
    } else if (STREQ(key, "mkdir")) {
      mkdir_p(val);
    } else if (STREQ(key, "mktmpfs")) {
      if (access(val, F_OK) != 0)
        mkdir_p(val);
      checked_mount("tmpfs", val, "tmpfs", 0, NULL);
    } else if (STREQ(key, "chroot")) {
      checked_chroot(val);
    } else if (STREQ(key, "pivot_root")) {
      char new_root[FILENAME_MAX], putold[FILENAME_MAX];
      if (sscanf(val, "%[^:]:%[^:]", new_root, putold) == 2) {
        checked_pivot_root(new_root, putold);
      } else {
        fprintf(stderr, "wrong format to pivot_root");
        return EZ_ERROR_CORRUPT;
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
      char **args = parse_arg(val);
      execv(args[0], args);
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
    if (access(key, F_OK) == 0) {
      if (status->overwrite == STRATEGY_SKIP)
        break;
      if (status->overwrite == STRATEGY_ERROR) {
        fprintf(stderr, "File %s exists!\n", key);
        return EZ_ERROR_CORRUPT;
      }
    }
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
    mkdir(key, mode);
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
  free(buffer);
  if (fd != -1)
    close(fd);
  return EZ_ERROR_SYSCALL;
}

EZ_RET my_callback(void *user, EZ_TYPE type, ...) {
  va_list list;
  va_start(list, type);
  EZ_RET ret = my_callback_v(user, type, list);
  va_end(list);
  return ret;
}

int main(int argc, char *argv[]) {
  g_argv = argv;
  FILE *file;
  EZ_RET ret;
  file = getpayload(NULL);
  if (!file)
    goto err;
  if (geteuid() != 0) {
    int uid = geteuid(), gid = getegid();
    checked_unshare(CLONE_NEWUSER);
    deny_to_setgroups();
    map_to_root(uid, "/proc/self/uid_map");
    map_to_root(gid, "/proc/self/gid_map");
  }
  checked_unshare(CLONE_NEWNS);
  pkstatus status;
  check_err(ez_unpack(file, true, my_callback, &status));
  return 0;
err:
  fprintf(stderr, "%s\n", ez_error_string(ret));
  return ret;
}