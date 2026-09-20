#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

volatile unsigned char qdmsan_strdup_oob_sink;

int main(void) {
  char *copy = strdup("abc");
  if (!copy) { return 77; }
  qdmsan_strdup_oob_sink = ((volatile unsigned char *)copy)[4];
  free(copy);
  return 0;
}
