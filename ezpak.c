#include "ezpak.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <unistd.h>

struct ez_block {
  enum EZ_TYPE type : 4;
  uint16_t mode : 12;
  uint64_t len : 48;
  char buffer[0];
};

typedef struct ez_block ez_block;

#define checked_read(ptr, size, stream)                                        \
  ({                                                                           \
    int ret = fread(ptr, size, 1, stream);                                     \
    if (ret != 1) {                                                            \
      fprintf(stderr, "fread: %s\n",                                           \
              ferror(stream) ? "Unknown error" : "EOF");                       \
      return EZ_ERROR_SYSCALL;                                                 \
    }                                                                          \
    ret;                                                                       \
  })

#define checked_getdelim(ptr, size, delim, stream)                             \
  ({                                                                           \
    ssize_t ret = getdelim(ptr, size, delim, stream);                          \
    if (ret == -1) {                                                           \
      perror("getdelim");                                                      \
      return EZ_ERROR_SYSCALL;                                                 \
    }                                                                          \
    ret;                                                                       \
  })

#define checked_write(ptr, size, stream)                                       \
  ({                                                                           \
    int ret = fwrite(ptr, size, 1, stream);                                    \
    if (ret != 1) {                                                            \
      perror("fwrite");                                                        \
      return EZ_ERROR_SYSCALL;                                                 \
    }                                                                          \
    ret;                                                                       \
  })

#define checked_lseek(fd, off, wh)                                             \
  ({                                                                           \
    off_t ret = lseek(fd, off, wh);                                            \
    if (ret == -1) {                                                           \
      perror("lseek");                                                         \
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

EZ_RET ez_begin(FILE *file) {
  checked_write("EZPK", 4, file);
  return EZ_OK;
}

EZ_RET ez_end(FILE *file) {
  ez_block block = {.type = EZ_T_END, .mode = 0, .len = 0};
  checked_write(&block, sizeof(ez_block), file);
  return EZ_OK;
}

EZ_RET ez_pop(FILE *file) {
  ez_block block = {.type = EZ_T_POP, .mode = 0, .len = 0};
  checked_write(&block, sizeof(ez_block), file);
  return EZ_OK;
}

EZ_RET ez_manifest(FILE *file, char const *key, char const *value) {
  size_t keylen = strlen(key), vallen = strlen(value);
  assert(keylen != 0);
  ez_block block = {.type = EZ_T_MAN, .mode = 0, .len = keylen + vallen + 2};
  checked_write(&block, sizeof(ez_block), file);
  checked_write(key, keylen + 1, file);
  checked_write(value, vallen + 1, file);
  return EZ_OK;
}

EZ_RET ez_push_file(FILE *file, char const *key, int16_t mode,
                    char const *content, uint64_t length) {
  size_t keylen = strlen(key);
  assert(keylen != 0);
  ez_block block = {.type = EZ_T_REG, .mode = mode, .len = keylen + length + 1};
  checked_write(&block, sizeof(ez_block), file);
  checked_write(key, keylen + 1, file);
  checked_write(content, length, file);
  return EZ_OK;
}

EZ_RET ez_push_folder(FILE *file, char const *key, int16_t mode) {
  size_t keylen = strlen(key);
  assert(keylen != 0);
  ez_block block = {.type = EZ_T_DIR, .mode = mode, .len = keylen + 1};
  checked_write(&block, sizeof(ez_block), file);
  checked_write(key, keylen + 1, file);
  return EZ_OK;
}

EZ_RET ez_push_link(FILE *file, char const *key, char const *target) {
  size_t keylen = strlen(key), vallen = strlen(target);
  assert(keylen != 0 && vallen != 0);
  ez_block block = {.type = EZ_T_LNK, .mode = 0, .len = keylen + vallen + 2};
  checked_write(&block, sizeof(ez_block), file);
  checked_write(key, keylen + 1, file);
  checked_write(target, vallen + 1, file);
  return EZ_OK;
}

EZ_RET ez_push(FILE *file, enum EZ_TYPE type, ...) {
  va_list list;
  va_start(list, type);
  EZ_RET ret = ez_push_v(file, type, list);
  va_end(list);
  return EZ_OK;
}

EZ_RET ez_push_v(FILE *file, enum EZ_TYPE type, va_list list) {
  switch (type) {
  case EZ_T_END:
    return ez_end(file);
  case EZ_T_MAN: {
    char const *key = va_arg(list, char const *);
    char const *value = va_arg(list, char const *);
    return ez_manifest(file, key, value);
  }
  case EZ_T_REG: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    char const *content = va_arg(list, char const *);
    size_t length = va_arg(list, uint64_t);
    return ez_push_file(file, key, mode, content, length);
  }
  case EZ_T_LNK: {
    char const *key = va_arg(list, char const *);
    char const *content = va_arg(list, char const *);
    return ez_push_link(file, key, content);
  }
  case EZ_T_DIR: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    return ez_push_folder(file, key, mode);
  }
  case EZ_T_POP: {
    return ez_pop(file);
  }
  case EZ_T_SENDFILE: {
    char const *key = va_arg(list, char const *);
    uint16_t mode = va_arg(list, int);
    int fd = va_arg(list, int);
    off_t *off = va_arg(list, off_t *);
    uint64_t length = va_arg(list, uint64_t);
    return ez_send_file(file, key, mode, fd, off, length);
  }
  default:
    return EZ_ERROR_NOT_IMPL;
  }
}

EZ_RET ez_send_file(FILE *file, char const *key, int16_t mode, int fd,
                    off_t *off, uint64_t length) {
  size_t keylen = strlen(key), len = length ?: checked_lseek(fd, 0, SEEK_END);
  assert(keylen != 0);
  ez_block block = {.type = EZ_T_REG, .mode = mode, .len = keylen + len + 1};
  checked_write(&block, sizeof(ez_block), file);
  checked_write(key, keylen + 1, file);
  fflush(file);
  checked_sendfile(fileno(file), fd, off, len);
  return EZ_OK;
}

#define checked_callback(...)                                                  \
  ({                                                                           \
    EZ_RET ret = callback(__VA_ARGS__);                                        \
    if (ret != EZ_OK)                                                          \
      return EZ_ERROR_CALLBACK | ret;                                          \
  })

EZ_RET ez_unpack(FILE *file, bool use_fd, ez_callback callback, void *arg) {
  // check magic
  char magic[4];
  char *key_buffer = NULL, *val_buffer = NULL;
  size_t key_len = 0, val_len = 0;
  ssize_t slen = 0;
  size_t size = 0;
  checked_read(magic, 4, file);
  if (memcmp(magic, "EZPK", 4) != 0)
    return EZ_ERROR_MAGIC;
  while (1) {
    ez_block block;
    checked_read(&block, sizeof(block), file);
    switch (block.type) {
    case EZ_T_END:
      checked_callback(arg, block.type);
      return EZ_OK;
    case EZ_T_LNK:
    case EZ_T_MAN:
      checked_getdelim(&key_buffer, &key_len, 0, file);
      checked_getdelim(&val_buffer, &val_len, 0, file);
      checked_callback(arg, block.type, key_buffer, val_buffer);
      break;
    case EZ_T_REG:
      slen = checked_getdelim(&key_buffer, &key_len, 0, file);
      size = block.len - slen;
      if (use_fd) {
        off_t cur = ftello(file);
        off_t copied = cur;
        checked_callback(arg, EZ_T_SENDFILE, key_buffer, block.mode,
                         fileno(file), &copied, size);
        fseek(file, cur + size, SEEK_SET);
      } else {
        char *temp = (char *)malloc(size);
        checked_read(temp, size, file);
        checked_callback(arg, block.type, key_buffer, block.mode, temp, size);
        free(temp);
      }
      break;
    case EZ_T_DIR:
      checked_getdelim(&key_buffer, &key_len, 0, file);
      checked_callback(arg, block.type, key_buffer, block.mode);
      break;
    case EZ_T_POP:
      checked_callback(arg, block.type);
      break;
    default:
      return EZ_ERROR_CORRUPT;
    }
  }
  return EZ_ERROR_CORRUPT;
}

char const *ez_error_string(EZ_RET value) {
  switch (value) {
  case EZ_OK:
    return "OK";
  case EZ_ERROR_SYSCALL:
    return "Syscall error";
  case EZ_ERROR_NOT_IMPL:
    return "Function is not implemented";
  case EZ_ERROR_MAGIC:
    return "Magic number is not matched";
  case EZ_ERROR_CORRUPT:
    return "File is corrupted or unreadable";
  default:
    if (value & EZ_ERROR_CALLBACK)
      switch (value & !EZ_ERROR_CALLBACK) {
      case EZ_ERROR_SYSCALL:
        return "Callback error: Syscall error";
      case EZ_ERROR_NOT_IMPL:
        return "Callback error: Function is not implemented";
      case EZ_ERROR_MAGIC:
        return "Callback error: Magic number is not matched";
      case EZ_ERROR_CORRUPT:
        return "Callback error: File is corrupted or unreadable";
      }
    return "Unknown error";
  }
}