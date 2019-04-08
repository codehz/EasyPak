#define _GNU_SOURCE

#include "ezpak.h"
#include "ezutils.h"
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

#define checked_sendfile(out_fd, in_fd, offset, count)                         \
  ({                                                                           \
    ssize_t ret = sendfile(out_fd, in_fd, offset, count);                      \
    if (ret == -1) {                                                           \
      perror("sendfile");                                                      \
      return EZ_ERROR_SYSCALL;                                                 \
    }                                                                          \
    ret;                                                                       \
  })

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
  check_err(build_pack(output, input));
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