#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum EZ_TYPE {
  // End of file
  EZ_T_END = 0,
  // Meta info
  EZ_T_MAN = 1,
  // Regular file
  EZ_T_REG = 2,
  // Soft link
  EZ_T_LNK = 3,
  // Folder
  EZ_T_DIR = 4,
};

#define EZ_T_SENDFILE 0x100

int ez_begin(FILE *file);

int ez_end(FILE *file);

int ez_manifest(FILE *file, char const *key, char const *value);

int ez_push_file(FILE *file, char const *key, int16_t mode, char const *content,
                 uint64_t length);

int ez_push_folder(FILE *file, char const *key, int16_t mode);

int ez_push_link(FILE *file, char const *key, char const *target);

int ez_push(FILE *file, enum EZ_TYPE type, ...);

int ez_push_v(FILE *file, enum EZ_TYPE type, va_list list);

int ez_send_file(FILE *file, char const *key, int16_t mode, int fd, off_t *off,
                 uint64_t length);

typedef int (*ez_callback)(void *user, enum EZ_TYPE type, ...);

int ez_unpack(FILE *file, bool use_fd, ez_callback callback, void *arg);