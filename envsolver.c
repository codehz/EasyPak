#include "envsolver.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *envsolver(char const *input) {
  if (!*input)
    return NULL;
  char *ret = calloc(1, 1024), *cur = ret;
  char buffer[1024] = {0}, *bufcur = &buffer[0];
  int stage = 0;
  while (*input) {
    switch (stage) {
    case 0:
      switch (*input) {
      case '$':
        stage = 1;
        input++;
        break;
      case '\\':
        stage = 3;
        input++;
        break;
      default:
        *cur++ = *input++;
        break;
      }
      break;
    case 1:
    case 2:
      if (isalpha(*input) || *input == '_' || (stage == 2 && isdigit(*input))) {
        *bufcur++ = *input++;
        stage = 2;
      } else {
        char *enval = getenv(buffer);
        if (enval) {
          while (*enval)
            *cur++ = *enval++;
        }
        memset(buffer, 0, 1024);
        bufcur = &buffer[0];
        stage = 0;
      }
      break;
    case 3:
      *cur++ = *input++;
      break;
    }
  }
  if (stage == 1 || stage == 2) {
    char *enval = getenv(buffer);
    if (enval) {
      while (*enval)
        *cur++ = *enval++;
    }
  }
  return ret;
}