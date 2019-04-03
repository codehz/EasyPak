#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum EZ_TYPE {
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
} EZ_TYPE;

#define EZ_T_SENDFILE 0x100

typedef enum EZ_RET {
  EZ_OK,
  EZ_ERROR_SYSCALL,
  EZ_ERROR_NOT_IMPL,
  EZ_ERROR_MAGIC,
  EZ_ERROR_CORRUPT,
  EZ_ERROR_CALLBACK = 0x100,
} EZ_RET;

EZ_RET ez_begin(FILE *file);

EZ_RET ez_end(FILE *file);

EZ_RET ez_manifest(FILE *file, char const *key, char const *value);

EZ_RET ez_push_file(FILE *file, char const *key, int16_t mode,
                         char const *content, uint64_t length);

EZ_RET ez_push_folder(FILE *file, char const *key, int16_t mode);

EZ_RET ez_push_link(FILE *file, char const *key, char const *target);

EZ_RET ez_push(FILE *file, EZ_TYPE type, ...);

EZ_RET ez_push_v(FILE *file, EZ_TYPE type, va_list list);

EZ_RET ez_send_file(FILE *file, char const *key, int16_t mode, int fd,
                         off_t *off, uint64_t length);

typedef EZ_RET (*ez_callback)(void *user, EZ_TYPE type, ...);

EZ_RET ez_unpack(FILE *file, bool use_fd, ez_callback callback, void *arg);