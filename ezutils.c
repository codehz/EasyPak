#include "ezutils.h"

static char *rwx[] = {"---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};
static __thread char modebuf[10];
static __thread char sizebuf[32];

char *printMode(uint16_t input) {
  memcpy(modebuf, rwx[(input >> 6) % 8], 3);
  memcpy(modebuf + 3, rwx[(input >> 3) % 8], 3);
  memcpy(modebuf + 6, rwx[input % 8], 3);
  modebuf[9] = 0;
  return modebuf;
}

char *readable_fs(double size) {
  int i = 0;
  const char *units[] = {"B",   "KiB", "MiB", "GiB", "TiB",
                         "PiB", "EiB", "ZiB", "YiB"};
  while (size > 1024) {
    size /= 1024;
    i++;
  }
  sprintf(sizebuf, "%.*f %s", i, size, units[i]);
  return sizebuf;
}

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

EZ_RET build_pack(FILE *output, FILE *input) {
  EZ_RET ret = EZ_OK;
  int dirfd = -1;

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

err:
  if (dirfd != -1)
    close(dirfd);
  return ret;
}