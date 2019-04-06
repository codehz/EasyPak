#include "parse_arg.h"
#include <stdlib.h>
#include <string.h>

enum parse_state {
  PARSE_EATING,
  PARSE_NORMAL,
  PARSE_STRING,
};
enum parse_escape_state {
  PARSE_ESCAPE_DISABLE,
  PARSE_ESCAPE_NONE,
  PARSE_ESCAPE_HEX
};

char **parse_arg(char const *input) {
  char **ret = calloc(sizeof(char *), 256), **head = ret;
  char *buffer = calloc(1, 1024), *buffer_head = buffer;
  enum parse_state status = PARSE_EATING;
  char quote = ' ';
  enum parse_escape_state escape = PARSE_ESCAPE_DISABLE;
  char hexbuf[3] = {0};
  int hexlen = 0;
  while (*input) {
    switch (escape) {
    case PARSE_ESCAPE_DISABLE:
      switch (status) {
      case PARSE_EATING:
        switch (*input) {
        case ' ':
        case '\t':
          input++;
          break;
        default:
          status = PARSE_NORMAL;
          break;
        }
        break;
      case PARSE_NORMAL:
        switch (*input) {
        case ' ':
          *head++ = buffer;
          buffer = buffer_head = calloc(1, 1024);
          status = PARSE_EATING;
          input++;
          break;
        case '"':
          status = PARSE_STRING;
          quote = '"';
          input++;
          break;
        case '\'':
          status = PARSE_STRING;
          quote = '\'';
          input++;
          break;
        case '\\':
          escape = PARSE_ESCAPE_NONE;
          input++;
          break;
        default:
          *buffer_head++ = *input++;
          break;
        }
        break;
      case PARSE_STRING:
        switch (*input) {
        case '\\':
          escape = PARSE_ESCAPE_NONE;
          input++;
          break;
        case '"':
        case '\'':
          if (*input == quote) {
            status = PARSE_NORMAL;
            input++;
            break;
          }
        default:
          *buffer_head++ = *input++;
          break;
        }
        break;
      }
      break;
    case PARSE_ESCAPE_NONE:
      switch (*input) {
      case 'x':
        escape = PARSE_ESCAPE_HEX;
        hexlen = 0;
        input++;
        break;
      case 'n':
        *buffer_head++ = '\n';
        input++;
        break;
      case 't':
        *buffer_head++ = '\t';
        input++;
        break;
      case 'a':
        *buffer_head++ = '\a';
        input++;
        break;
      case 'b':
        *buffer_head++ = '\b';
        input++;
        break;
      case 'f':
        *buffer_head++ = '\f';
        input++;
        break;
      case 'r':
        *buffer_head++ = '\r';
        input++;
        break;
      case 'v':
        *buffer_head++ = '\v';
        input++;
        break;
      case '0':
        *buffer_head++ = '\0';
        input++;
        break;
      default:
        *buffer_head++ = *input++;
        escape = PARSE_ESCAPE_DISABLE;
        break;
      }
      break;
    case PARSE_ESCAPE_HEX:
      if ((*input >= '0' && *input <= '9') ||
          (*input >= 'a' && *input <= 'f') ||
          (*input >= 'A' && *input <= 'F')) {
        hexbuf[hexlen++] = *input++;
        if (hexlen == 2) {
          *buffer_head++ = strtol(hexbuf, NULL, 16);
          escape = PARSE_ESCAPE_DISABLE;
          break;
        }
      } else {
        *buffer_head++ = *input++;
        escape = PARSE_ESCAPE_DISABLE;
        break;
      }
      break;
    }
  }

  if (buffer_head != buffer)
    *head++ = buffer;
  else
    free(buffer);

  return ret;
}