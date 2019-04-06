#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef enum file_type { FILE_REGULAR, FILE_LINK, FILE_FOLDER } file_type;

typedef struct file_tree {
  file_type type;
  size_t id;
  int mode;
  unsigned long name_hash;
  char *name;
  struct file_tree *parent;
  struct file_tree *next;
  union {
    struct {
      size_t offset, length;
    };
    char *link;
    struct file_tree *child;
  };
} file_tree;

extern FILE *basefile;

int setup_fuse(char *target, file_tree *tree);

unsigned long hash(char const *str);