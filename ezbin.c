#define _GNU_SOURCE

#include "ezpak.h"
#include "payload.h"
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
    int fd = open(path, ##__VA_ARGS__);                                        \
    if (fd == -1) {                                                            \
      perror("open");                                                          \
      goto err;                                                                \
    }                                                                          \
    fd;                                                                        \
  })

#define checked_fdopendir(fd)                                                  \
  ({                                                                           \
    DIR *temp = fdopendir(fd);                                                 \
    if (temp == NULL) {                                                        \
      perror("opendir");                                                       \
      goto err;                                                                \
    };                                                                         \
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

#define checked_sendfile(out_fd, in_fd, offset, count)                         \
  ({                                                                           \
    ssize_t ret = sendfile(out_fd, in_fd, offset, count);                      \
    if (ret == -1) {                                                           \
      perror("sendfile");                                                      \
      return EZ_ERROR_SYSCALL;                                                 \
    }                                                                          \
    ret;                                                                       \
  })

#define check_err(body)                                                        \
  if ((ret = body) != 0)                                                       \
    goto err;

char *rwx[] = {"---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};

__thread char modebuf[10];

char *printMode(uint16_t input) {
  memcpy(modebuf, rwx[(input >> 6) % 8], 3);
  memcpy(modebuf + 3, rwx[(input >> 3) % 8], 3);
  memcpy(modebuf + 6, rwx[input % 8], 3);
  modebuf[9] = 0;
  return modebuf;
}

#define PAD 2

EZ_RET pack_iterator(FILE *file, int dirfd, int level) {
  DIR *root = NULL;
  char link_buffer[FILENAME_MAX];
  int fd = -1;
  EZ_RET ret = EZ_OK;
  root = checked_fdopendir(dirfd);
  while (1) {
    struct dirent *dir_entry = NULL;
    struct stat stat_buf;
    char *name = NULL;
    uint16_t mode;
    dir_entry = readdir(root);
    if (!dir_entry)
      break;
    name = dir_entry->d_name;
    if (name[0] == '.')
      continue;
    switch (dir_entry->d_type) {
    case DT_REG:
      fd = checked_openat(dirfd, name, O_RDONLY);
      checked_fstat(fd, &stat_buf);
      mode = stat_buf.st_mode & 0777;
      fprintf(stderr, "-%s %*s%s\n", printMode(mode), level * PAD, "", name);
      check_err(ez_send_file(file, name, mode, fd, 0, stat_buf.st_size));
      close(fd);
      fd = -1;
      break;
    case DT_LNK:
      checked_readlinkat(dirfd, name, link_buffer, FILENAME_MAX);
      fprintf(stderr, "lrwxrwxrwx %*s%s -> %s\n", level * PAD, "", name,
              link_buffer);
      check_err(ez_push_link(file, name, link_buffer));
      break;
    case DT_DIR:
      fd = checked_openat(dirfd, name, O_DIRECTORY);
      checked_fstat(fd, &stat_buf);
      mode = stat_buf.st_mode & 0777;
      fprintf(stderr, "d%s %*s%s\n", printMode(mode), level * PAD, "", name);
      check_err(ez_push_folder(file, name, mode));
      check_err(pack_iterator(file, fd, level + 1));
      check_err(ez_pop(file));
      close(fd);
      fd = -1;
      break;
    default:
      break;
    }
  }
  return EZ_OK;
err:
  printf("ret:%d\n", ret);
  if (fd != -1)
    close(fd);
  return ret || EZ_ERROR_SYSCALL;
}

int main(int argc, char *argv[]) {
  EZ_RET ret = EZ_OK;
  size_t binsize = 0;
  int dirfd = -1;
  FILE *payload = getpayload(&binsize);
  if (!payload)
    goto payload_err;
  if (argc != 3)
    goto arg_err;
  FILE *output = NULL, *input = NULL;
  output = checked_fopen(argv[1], "wb");
  input = checked_fopen(argv[2], "rb");
  checked_sendfile(fileno(output), fileno(payload), NULL, binsize);
  fclose(payload);
  check_err(ez_begin(output));

  char line[65536];
  while (fgets(line, sizeof line, input) != NULL) {
    if (strlen(line) == 0)
      continue;
    if (line[0] == '@') {
      dirfd = checked_open(strtok(line + 1, "\n"), O_DIRECTORY);
      check_err(pack_iterator(output, dirfd, 0));
    } else if (line[0] == '#') {
      continue;
    } else {
      char *key = strtok(line, " \n");
      char *val = strtok(NULL, "\n");
      printf("m--------- %s: %s\n", key, val);
      check_err(ez_manifest(output, key, val ?: ""));
    }
  }

  check_err(ez_end(output));
  fclose(output);
  fclose(input);
  chmod(argv[1], 0755);
  return 0;

payload_err:
  return -1;

arg_err:
  fprintf(stderr, "usage: %s targetexe buildfile\n", argv[0]);
  return -2;

err:
  fprintf(stderr, "%s\n", ez_error_string(ret));
  if (dirfd != -1)
    close(dirfd);
  if (input)
    fclose(input);
  if (output)
    fclose(output);
  return ret;
}