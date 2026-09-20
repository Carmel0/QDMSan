#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* fwrite calls a user cookie writer while libqdmsan's recursion guard is
 * active.  Reallocating a previously managed pointer must retain its owner. */
static unsigned char *buffer;
static unsigned step;
static int failed;

static ssize_t writer(void *cookie, const char *data, size_t size) {
  (void)cookie;
  (void)data;
  unsigned char *next;
  if (step == 0 || step == 1) {
    next = realloc(buffer, step == 0 ? 128 : 4);
    if (!next || next[0] != 19 || next[3] != 37) failed = 1;
    if (next) buffer = next;
  } else if (step == 2) {
    volatile size_t huge = SIZE_MAX;
    errno = 0;
    next = realloc(buffer, huge);
    if (next || errno != ENOMEM || buffer[0] != 19 || buffer[3] != 37) {
      failed = 1;
    }
  } else if (step == 3) {
    if (realloc(buffer, 0)) failed = 1;
    buffer = NULL;
  } else if (step == 4) {
    /* malloc under the recursion guard is a foreign libc allocation. */
    buffer = malloc(8);
    if (!buffer) failed = 1;
    else { buffer[0] = 19; buffer[3] = 37; }
  } else if (step == 5) {
    next = realloc(buffer, 64);
    if (!next || next[0] != 19 || next[3] != 37) failed = 1;
    if (next) buffer = next;
  } else {
    free(buffer);
    buffer = NULL;
  }
  ++step;
  return size;
}

int main(void) {
  cookie_io_functions_t funcs = {.write = writer};
  FILE *stream = fopencookie(NULL, "w", funcs);
  if (!stream || setvbuf(stream, NULL, _IONBF, 0)) return 2;
  buffer = malloc(8);
  if (!buffer) return 3;
  memset(buffer, 0, 8);
  buffer[0] = 19;
  buffer[3] = 37;
  for (unsigned i = 0; i < 7; ++i) {
    if (fwrite("x", 1, 1, stream) != 1 || failed) return 4;
  }
  return fclose(stream) || failed;
}
