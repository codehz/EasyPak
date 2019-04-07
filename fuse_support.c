#define FUSE_USE_VERSION 31

#include "fuse_support.h"
#include <assert.h>
#include <errno.h>
#include <fuse3/fuse.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <unistd.h>

FILE *basefile;
static file_tree *current_tree;
static int event;

unsigned long hash(char const *str) {
  unsigned long hash = 5381;
  int c;

  while ((c = *(unsigned char const *)str++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

  return hash;
}

file_tree *find_path(char const *raw_path) {
  char *saved = NULL;
  char *path = strdup(raw_path + 1);
  char *temp = NULL, *part = NULL;
  file_tree *cur = current_tree, *prev = NULL;
  bool folder = false;
  for (temp = path;; temp = NULL) {
    part = strtok_r(temp, "/", &saved);
    if (part == NULL)
      break;
    unsigned long hashed = hash(part);
    while (cur) {
      if (cur->name_hash == hashed && strcmp(cur->name, part) == 0) {
        folder = false;
        if (cur->type == FILE_FOLDER) {
          prev = cur;
          cur = cur->child;
          folder = true;
        }
        goto end;
      }
      cur = cur->next;
    }
    free(path);
    return NULL;
  end:
    continue;
  }
  free(path);
  if (folder && prev && prev->child == cur)
    return prev;
  return cur;
}

int get_nbro(file_tree *cur) {
  int n = 2;
  while (cur) {
    n += cur->type == FILE_FOLDER;
    cur = cur->next;
  }
  return n;
}

void free_file_tree(file_tree *tree) {
  if (!tree)
    return;
  free(tree->name);
  switch (tree->type) {
  case FILE_REGULAR:
    break;
  case FILE_LINK:
    free(tree->link);
    break;
  case FILE_FOLDER:
    free_file_tree(tree->child);
    break;
  }
  file_tree *next = tree->next;
  free(tree);
  free_file_tree(next);
}

static void *my_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
  cfg->kernel_cache = 1;
  eventfd_write(event, 1);
  close(event);
  return NULL;
}

void fillattr(struct stat *stbuf, file_tree *found) {
  switch (found->type) {
  case FILE_REGULAR:
    stbuf->st_mode = S_IFREG | (found->mode & 0777);
    stbuf->st_nlink = 1;
    stbuf->st_size = found->length;
    break;
  case FILE_LINK:
    stbuf->st_mode = S_IFLNK | (found->mode & 0777);
    stbuf->st_nlink = 1;
    break;
  case FILE_FOLDER:
    stbuf->st_mode = S_IFDIR | (found->mode & 0777);
    stbuf->st_nlink = get_nbro(found->child);
    break;
  }
}

static int my_getattr(const char *path, struct stat *stbuf,
                      struct fuse_file_info *fi) {
  int res = 0;
  if (strcmp(path, "/") == 0) {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = get_nbro(current_tree);
  } else {
    file_tree *found = find_path(path);
    if (!found) {
      res = -ENOENT;
    } else {
      fillattr(stbuf, found);
    }
  }
  return res;
}

static int my_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
  file_tree *cur = NULL;
  if (strcmp(path, "/") == 0) {
    cur = current_tree;
  } else {
    file_tree *found = find_path(path);
    if (!found)
      return -ENOENT;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    cur = found->child;
  }

  while (cur) {
    struct stat stbuf;
    fillattr(&stbuf, cur);
    filler(buf, cur->name, &stbuf, 0, FUSE_FILL_DIR_PLUS);
    cur = cur->next;
  }
  return 0;
}

static int my_open(const char *path, struct fuse_file_info *fi) {
  if ((fi->flags & O_ACCMODE) != O_RDONLY)
    return -EACCES;
  if (strcmp(path, "/") == 0 || find_path(path))
    return 0;
  return -ENOENT;
}

static int my_readlink(const char *path, char *buf, size_t bufsiz) {
  if (strcmp(path, "/") == 0)
    return -EINVAL;
  file_tree *found = find_path(path);
  if (!found)
    return ENOENT;
  if (found->type != FILE_LINK)
    return -EINVAL;
  strncpy(buf, found->link, bufsiz);
  return 0;
}

static int my_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
  if (strcmp(path, "/") == 0)
    return -EISDIR;
  file_tree *found = find_path(path);
  if (!found)
    return -ENOENT;
  if (found->type == FILE_LINK)
    return -EINVAL;
  if (found->type == FILE_FOLDER)
    return -EISDIR;
  if (offset > found->length)
    return 0;
  if (offset + size > found->length)
    size = found->length - offset;
  int fd = fileno(basefile);
  int ret = lseek(fd, found->offset + offset, SEEK_SET);
  if (ret == -1)
    return -errno;
  ret = read(fd, buf, size);
  if (ret == -1)
    return -errno;
  return ret;
}

static int my_access(const char *path, int op) {
  if (strcmp(path, "/") == 0) {
    return 0;
  }
  file_tree *found = find_path(path);
  if (!found)
    return -ENOENT;
  if (found->type == FILE_LINK)
    return 0;
  switch (op) {
  case F_OK:
    return 0;
  case R_OK:
    return found->mode & 0400 ? 0 : -EACCES;
  case W_OK:
    return found->mode & 0200 ? 0 : -EACCES;
  case X_OK:
    return found->mode & 0100 ? 0 : -EACCES;
  }
  return -EINVAL;
}

static struct fuse_operations my_oper = {
    .init = my_init,
    .getattr = my_getattr,
    .readdir = my_readdir,
    .readlink = my_readlink,
    .open = my_open,
    .read = my_read,
    .access = my_access,
};

int setup_fuse(char *target, file_tree *tree) {
  char *args[] = {"easypak", target, "-f", "-o", "allow_other", NULL};
  event = eventfd(0, 0);
  pid_t pid = fork();
  if (pid < 0)
    return pid;
  if (pid == 0) {
    prctl(PR_SET_PDEATHSIG, SIGINT, 0, 0, 0);
    current_tree = tree;
    exit(fuse_main(5, args, &my_oper, NULL));
  }
  // free_file_tree(tree);
  eventfd_t e;
  eventfd_read(event, &e);
  close(event);
  return pid;
}