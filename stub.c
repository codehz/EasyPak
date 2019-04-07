#define _GNU_SOURCE

#include "envsolver.h"
#include "ezpak.h"
#include "fuse_support.h"
#include "parse_arg.h"
#include "payload.h"
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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
  pid_t lastpid;
  char *fuse_mode;
  file_tree *ft_root, *ft_current;
  bool ft_enter;
} pkstatus;

#define make_ft_node(node, key, T)                                             \
  file_tree *node = calloc(1, sizeof(file_tree));                              \
  node->type = T;                                                              \
  node->name = strdup(key);                                                    \
  node->name_hash = hash(key);

#define insert_ft_node(status, node)                                           \
  ({                                                                           \
    if (!status->ft_root) {                                                    \
      status->ft_root = status->ft_current = node;                             \
    } else {                                                                   \
      if (status->ft_enter) {                                                  \
        status->ft_current->child = node;                                      \
        node->parent = status->ft_current;                                     \
      } else {                                                                 \
        status->ft_current->next = node;                                       \
        node->parent = status->ft_current->parent;                             \
      }                                                                        \
      status->ft_current = node;                                               \
      status->ft_enter = false;                                                \
    }                                                                          \
  })

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
    if (status->fuse_mode) {
      status->ft_current = NULL;
      status->ft_enter = false;
      setup_fuse(status->fuse_mode, status->ft_root);
      free(status->fuse_mode);
      status->ft_root = NULL;
      status->fuse_mode = NULL;
    }
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
      char *solved = envsolver(val);
      mkdir_p(solved);
      checked_chdir(solved);
      free(solved);
    } else if (STREQ(key, "mkdir")) {
      char *solved = envsolver(val);
      mkdir_p(solved);
      free(solved);
    } else if (STREQ(key, "mktmpfs")) {
      char *solved = envsolver(val);
      if (access(solved, F_OK) != 0)
        mkdir_p(solved);
      checked_mount("tmpfs", solved, "tmpfs", 0, NULL);
      free(solved);
    } else if (STREQ(key, "chroot")) {
      char *solved = envsolver(val);
      checked_chroot(solved);
      free(solved);
    } else if (STREQ(key, "pivot_root")) {
      char new_root[FILENAME_MAX], putold[FILENAME_MAX];
      char *solved = envsolver(val);
      if (sscanf(solved, "%[^:]:%[^:]", new_root, putold) == 2) {
        checked_pivot_root(new_root, putold);
      } else {
        fprintf(stderr, "wrong format to pivot_root");
        return EZ_ERROR_CORRUPT;
      }
      free(solved);
    } else if (STREQ(key, "bind")) {
      char from[FILENAME_MAX], to[FILENAME_MAX];
      char *solved = envsolver(val);
      if (sscanf(solved, "%[^:]:%[^:]", from, to) == 2) {
        checked_mount(from, to, "tmpfs", MS_BIND | MS_REC | MS_PRIVATE, NULL);
      } else {
        fprintf(stderr, "wrong format to mount");
        return EZ_ERROR_CORRUPT;
      }
      free(solved);
    } else if (STREQ(key, "exec")) {
      char *solved = envsolver(val);
      char **args = parse_arg(solved);
      execv(args[0], args);
      perror("execv");
      exit(254);
    } else if (STREQ(key, "exec-background")) {
      pid_t pid = fork();
      if (pid < 0) {
        perror("execv");
        exit(254);
      }
      if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGINT);
        char *solved = envsolver(val);
        char **args = parse_arg(solved);
        execv(args[0], args);
        perror("execv");
        exit(254);
      }
      status->lastpid = pid;
    } else if (STREQ(key, "wait")) {
      waitpid(status->lastpid, NULL, 0);
    } else if (STREQ(key, "waitdir")) {
      int ifd = inotify_init();
      char *solved = envsolver(val);
      inotify_add_watch(ifd, solved,
                        IN_MODIFY | IN_CREATE | IN_DELETE | IN_ONESHOT);
      free(solved);
      char temp[1024];
      if (read(ifd, &temp, sizeof temp) < 0) {
        perror("inotify");
        exit(254);
      }
      close(ifd);
    } else if (STREQ(key, "exec-passthru")) {
      char *solved = envsolver(val);
      execv(solved, g_argv);
      perror("execv");
      exit(254);
    } else if (STREQ(key, "fuse")) {
      if (strlen(val) == 0) {
        status->fuse_mode = strdup(".");
      } else {
        status->fuse_mode = envsolver(val);
      }
    } else if (STREQ(key, "env")) {
      assert(strlen(val) != 0);
      char *solved = envsolver(val);
      char *skey = strtok(solved, "=");
      char *sval = strtok(NULL, "=");
      if (sval)
        setenv(skey, sval, 1);
      else
        unsetenv(skey);
    } else if (STREQ(key, "option")) {
      assert(strlen(val) != 0);
      char *solved = envsolver(val);
      char *skey = strtok(solved, "=");
      char *sval = strtok(NULL, "=");
      if (sval)
        setenv(skey, sval, 0);
      else
        return EZ_ERROR_CORRUPT;
    } else {
      fprintf(stderr, "unsupported: %s\n", key);
      return EZ_ERROR_CORRUPT;
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
    if (status->fuse_mode) {
      make_ft_node(node, key, FILE_REGULAR);
      node->mode = mode;
      node->offset = *off;
      node->length = size;
      insert_ft_node(status, node);
    } else {
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
    }
    break;
  }
  case EZ_T_LNK: {
    char const *key = va_arg(list, char const *);
    char const *val = va_arg(list, char const *);
    if (status->fuse_mode) {
      make_ft_node(node, key, FILE_LINK);
      node->link = strdup(val);
      insert_ft_node(status, node);
    } else {
      checked_symlink(val, key);
    }
    break;
  }
  case EZ_T_DIR: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    if (status->fuse_mode) {
      make_ft_node(node, key, FILE_FOLDER);
      node->mode = mode;
      insert_ft_node(status, node);
      status->ft_enter = true;
    } else {
      mkdir(key, mode);
      checked_chdir(key);
    }
    break;
  }
  case EZ_T_POP:
    if (status->fuse_mode) {
      if (status->ft_enter) {
        status->ft_enter = false;
      } else {
        assert(status->ft_current);
        assert(status->ft_current->parent);
        status->ft_current = status->ft_current->parent;
      }
    } else {
      checked_chdir("..");
    }
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
  FILE *file = NULL;
  EZ_RET ret = EZ_OK;
  file = getpayload(NULL);
  basefile = file;
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
  pkstatus status = {0};
  check_err(ez_unpack(file, true, my_callback, &status));
  return 0;
err:
  fprintf(stderr, "%s\n", ez_error_string(ret));
  return ret;
}