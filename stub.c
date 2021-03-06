#define _GNU_SOURCE

#include "envsolver.h"
#include "ezpak.h"
#include "fuse_support.h"
#include "libutil/libutil.h"
#include "parse_arg.h"
#include "payload.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
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
      fprintf(stderr, "Failed to open %s\n", path);                            \
      perror("fopen");                                                         \
      goto err;                                                                \
    }                                                                          \
    temp;                                                                      \
  })

#define checked_open(path, ...)                                                \
  ({                                                                           \
    int fd = open(path, ##__VA_ARGS__);                                        \
    if (fd == -1) {                                                            \
      fprintf(stderr, "Failed to open %s\n", path);                            \
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

#define checked_freopen(path, mode, stream)                                    \
  ({                                                                           \
    FILE *ret = freopen(path, mode, stream);                                   \
    if (!ret) {                                                                \
      fprintf(stderr, "Failed to open %s\n", path);                            \
      perror("freopen");                                                       \
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

#define checked_mkfifo(...)                                                    \
  ({                                                                           \
    if (mkfifo(__VA_ARGS__) != 0) {                                            \
      perror("mkfifo");                                                        \
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
      fprintf(stderr, "failed to mkdir %s\n", path);                           \
      perror("mkdir");                                                         \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_chdir(path)                                                    \
  ({                                                                           \
    if (chdir(path) != 0) {                                                    \
      fprintf(stderr, "failed to chdir to %s\n", path);                        \
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
      fprintf(stderr, "failed to chroot to %s\n", path);                       \
      perror("chroot");                                                        \
      goto err;                                                                \
    }                                                                          \
  })

#define checked_pivot_root(new_root, putold)                                   \
  ({                                                                           \
    if (pivot_root(new_root, putold) != 0) {                                   \
      fprintf(stderr, "failed to pivot root to %s (old: %s)\n", new_root,      \
              putold);                                                         \
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
  int fork_level;
  char *fuse_mode;
  void *current_mapped;
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

EZ_RET my_callback(void *user, EZ_TYPE type, ...);

void handle_fuse(pkstatus *status) {
#ifdef FuseSupport
  status->ft_current = NULL;
  status->ft_enter = false;
  setup_fuse(status->fuse_mode, status->ft_root, status->current_mapped);
  free(status->fuse_mode);
  status->ft_root = NULL;
  status->fuse_mode = NULL;
#else
  abort();
#endif
}

static int delete_file_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  int rv = remove(fpath);
  if (rv) {
    perror(fpath);
  }
  return rv;
}

EZ_RET my_callback_v(void *user, EZ_TYPE type, va_list list) {
  EZ_RET ret = EZ_OK;
  pkstatus *status = user;
  char *buffer = NULL;
  FILE *tempfile = NULL;
  int fd = -1;
  if (type != EZ_T_MAN && status->fork_level) {
    printf("skipped\n");
    return EZ_OK;
  }
  switch (type) {
  case EZ_T_MAN: {
    char const *key = va_arg(list, char const *);
    char const *val = va_arg(list, char const *);
    if (status->fork_level) {
      if (STREQ(key, "exec") || STREQ(key, "exec-passthru") ||
          STREQ(key, "exec-passthru") || STREQ(key, "force-exit")) {
        status->fork_level--;
      } else if (STREQ(key, "fork") || STREQ(key, "fork")) {
        status->fork_level++;
      }
      return EZ_OK;
    }
    if (status->fuse_mode && !STREQ(key, "include")) {
      handle_fuse(status);
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
    } else if (STREQ(key, "run")) {
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
      waitpid(pid, NULL, 0);
    } else if (STREQ(key, "checked-run")) {
      pid_t pid = fork();
      if (pid < 0) {
        perror("execv");
        exit(254);
      }
      char *solved = envsolver(val);
      if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGINT);
        char **args = parse_arg(solved);
        execv(args[0], args);
        perror("execv");
        exit(254);
      }
      int status;
      waitpid(pid, &status, 0);
      if (status) {
        fprintf(stderr, "Failed to execute '%s'\n", solved);
        goto err;
      }
      free(solved);
    } else if (STREQ(key, "wait")) {
      waitpid(status->lastpid, NULL, 0);
    } else if (STREQ(key, "waitstop")) {
      waitpid(status->lastpid, NULL, WUNTRACED);
      kill(status->lastpid, SIGCONT);
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
    } else if (STREQ(key, "waitfile")) {
      char *solved = envsolver(val);
      setpriority(PRIO_PROCESS, getpid(), 20);
      while (1) {
        if (access(solved, F_OK) == 0)
          break;
        sched_yield();
      }
      free(solved);
      setpriority(PRIO_PROCESS, getpid(), 0);
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
      free(solved);
    } else if (STREQ(key, "option")) {
      assert(strlen(val) != 0);
      char *solved = envsolver(val);
      char *skey = strtok(solved, "=");
      char *sval = strtok(NULL, "=");
      if (sval)
        setenv(skey, sval, 0);
      else
        return EZ_ERROR_CORRUPT;
      free(solved);
    } else if (STREQ(key, "vfork")) {
      pid_t pid = vfork();
      if (pid < 0) {
        perror("execv");
        exit(254);
      }
      if (pid) {
        status->lastpid = pid;
      } else {
        prctl(PR_SET_PDEATHSIG, SIGINT);
      }
    } else if (STREQ(key, "fork")) {
      pid_t pid = fork();
      if (pid < 0) {
        perror("execv");
        exit(254);
      }
      if (pid) {
        status->lastpid = pid;
        status->fork_level = 1;
      } else {
        prctl(PR_SET_PDEATHSIG, SIGINT);
      }
    } else if (STREQ(key, "stdout")) {
      assert(strlen(val) != 0);
      char *solved = envsolver(val);
      checked_freopen(solved, "a", stdout);
      free(solved);
    } else if (STREQ(key, "stderr")) {
      assert(strlen(val) != 0);
      char *solved = envsolver(val);
      checked_freopen(solved, "a", stderr);
      free(solved);
    } else if (STREQ(key, "stdin")) {
      assert(strlen(val) != 0);
      char *solved = envsolver(val);
      checked_freopen(solved, "r", stdin);
      free(solved);
    } else if (STREQ(key, "mkfifo")) {
      assert(strlen(val) != 0);
      char *solved = envsolver(val);
      checked_mkfifo(solved, 0700);
      free(solved);
    } else if (STREQ(key, "touch")) {
      assert(strlen(val) != 0);
      char *solved = envsolver(val);
      fd = checked_open(solved, O_CREAT | O_WRONLY, 0755);
      close(fd);
      free(solved);
    } else if (STREQ(key, "force-exit")) {
      _exit(0);
    } else if (STREQ(key, "include")) {
      char *solved = envsolver(val);
      tempfile = checked_fopen(solved, "r");
      free(solved);
      struct stat stbuf;
      fstat(fileno(tempfile), &stbuf);
      void *temp = status->current_mapped;
      status->current_mapped =
          mmap(NULL, stbuf.st_size, PROT_READ, MAP_SHARED | MAP_NORESERVE,
               fileno(tempfile), 0);
      check_err(ez_unpack(tempfile, true, my_callback, status));
      if (status->fuse_mode) {
        handle_fuse(status);
      }
      munmap(status->current_mapped, stbuf.st_size);
      status->current_mapped = temp;
      fclose(tempfile);
      tempfile = NULL;
    } else if (STREQ(key, "daemon")) {
      if (daemon(true, false) == -1) {
        fprintf(stderr, "Failed to daemonize\n");
        return EZ_ERROR_SYSCALL;
      }
    } else if (STREQ(key, "pidfile")) {
      char *solved = envsolver(val);
      pid_t exists;
      struct pidfh *fh = pidfile_open(solved, 0700, NULL);
      if (!fh) {
        if (errno == EEXIST)
          fprintf(stderr, "Cannot create pid file, PID: %d\n", exists);
        else
          perror("Cannot create pid file");
        return EZ_ERROR_SYSCALL;
      }
      pidfile_write(fh);
    } else if (STREQ(key, "pause")) {
      pause();
    } else if (STREQ(key, "checkfile")) {
      char *solved = envsolver(val);
      if (access(solved, F_OK) != 0) {
        fprintf(stderr, "File '%s' not found!\n", solved);
        free(solved);
        goto err;
      }
      free(solved);
    } else if (STREQ(key, "findexe")) {
      char *solved = envsolver(val);
      char *saved = NULL;
      char *var = strtok_r(solved, "=", &saved);
      char *cmd = strtok_r(NULL, "=", &saved);
      if (!cmd) {
        fprintf(stderr, "Format error!\n");
        return EZ_ERROR_CORRUPT;
      }
      char *PATH = strdup(getenv("PATH"));
      saved = NULL;
      char *found = NULL;
      for (char *temp = PATH;; temp = NULL) {
        char *dir = strtok_r(temp, ":", &saved);
        if (!dir) {
          fprintf(stderr, "Executable file '%s' not found!\n", cmd);
          free(solved);
          free(PATH);
          goto err;
        }
        fd = open(dir, O_DIRECTORY);
        if (faccessat(fd, cmd, X_OK, 0) == 0) {
          close(fd);
          fd = -1;
          found = dir;
          break;
        }
        errno = 0;
        close(fd);
        fd = -1;
      }
      char *buffer = NULL;
      asprintf(&buffer, "%s/%s", found, cmd);
      setenv(var, buffer, true);
      free(buffer);
      free(solved);
      free(PATH);
    } else if (STREQ(key, "hostname")) {
      char *solved = envsolver(val);
      int ret = sethostname(solved, strlen(solved));
      free(solved);
      if (ret == -1) {
        fprintf(stderr, "Failed to set hostname: %s\n", strerror(errno));
        return EZ_ERROR_SYSCALL;
      }
    } else if (STREQ(key, "delete-self")) {
      char selfpath[256] = {0};
      ssize_t len = readlink("/proc/self/exe", selfpath, sizeof selfpath);
      selfpath[len] = 0;
      remove(selfpath);
    } else if (STREQ(key, "delete")) {
      char *solved = envsolver(val);
      struct stat path_stat;
      stat(solved, &path_stat);
      if (S_ISDIR(path_stat.st_mode)) {
        nftw(solved, delete_file_cb, 64, FTW_DEPTH | FTW_PHYS);
      } else {
        remove(solved);
      }
      free(solved);
    } else if (STREQ(key, "umount")) {
      char *solved = envsolver(val);
      if(umount(solved) == -1) {
        fprintf(stderr, "Failed to umount %s: %s\n", solved, strerror(errno));
        free(solved);
        return EZ_ERROR_SYSCALL;
      }
      free(solved);
    } else if (STREQ(key, "add-path")) {
      char *solved = envsolver(val);
      char *real = realpath(solved, NULL);
      char *old_PATH = getenv("PATH");
      char *new_PATH = malloc(strlen(old_PATH) + strlen(real) + 2);
      new_PATH[0] = 0;
      strcat(new_PATH, real);
      strcat(new_PATH, ":");
      strcat(new_PATH, old_PATH);
      setenv("PATH", new_PATH, 1);
      free(new_PATH);
      free(real);
      free(solved);
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
#ifdef FuseSupport
      make_ft_node(node, key, FILE_REGULAR);
      node->mode = mode;
      node->offset = *off;
      node->length = size;
      insert_ft_node(status, node);
#else
  abort();
#endif
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
#ifdef FuseSupport
      make_ft_node(node, key, FILE_LINK);
      node->link = strdup(val);
      insert_ft_node(status, node);
#else
      abort();
#endif
    } else {
      checked_symlink(val, key);
    }
    break;
  }
  case EZ_T_DIR: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    if (status->fuse_mode) {
#ifdef FuseSupport
      make_ft_node(node, key, FILE_FOLDER);
      node->mode = mode;
      insert_ft_node(status, node);
      status->ft_enter = true;
#else
      abort();
#endif
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
  if (tempfile)
    fclose(tempfile);
  return ret ?: EZ_ERROR_SYSCALL;
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
  struct stat sb;
  char wd[FILENAME_MAX];

  getcwd(wd, FILENAME_MAX);
  setenv("STARTWD", wd, 1);

  file = getpayload(NULL);
  fstat(fileno(file), &sb);
  void *mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED | MAP_NORESERVE,
                      fileno(file), 0);
  if (!file)
    goto err;
  if (geteuid() != 0) {
    int uid = geteuid(), gid = getegid();
    checked_unshare(CLONE_NEWUSER);
    deny_to_setgroups();
    map_to_root(uid, "/proc/self/uid_map");
    map_to_root(gid, "/proc/self/gid_map");
  }
  checked_unshare(CLONE_NEWNS | CLONE_NEWUTS);
  pkstatus status = {0};
  status.current_mapped = mapped;
  check_err(ez_unpack(file, true, my_callback, &status));
  return 0;
err:
  fprintf(stderr, "%s\n", ez_error_string(ret));
  return ret;
}