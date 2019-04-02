#include "ezpak.h"
#include <err.h>

int main(int argc, char *argv[]) {
  if (argc <= 2)
    goto err_args;
  /// TODO
  return 0;
err_args:
  errx(1, "%s (pack|unpack|test) pack dir", argv[0]);
}