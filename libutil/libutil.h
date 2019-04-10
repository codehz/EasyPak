#pragma once
#include <fcntl.h>

int flopen(const char *path, int flags, ...);
int flopenat(int dirfd, const char *path, int flags, ...);

struct pidfh;
struct pidfh *pidfile_open(const char *path, mode_t mode, pid_t *pidptr);
int pidfile_write(struct pidfh *pfh);
int pidfile_close(struct pidfh *pfh);
int pidfile_remove(struct pidfh *pfh);
int pidfile_fileno(const struct pidfh *pfh);