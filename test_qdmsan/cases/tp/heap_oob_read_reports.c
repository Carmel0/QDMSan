#include <stddef.h>
#include <stdlib.h>

volatile unsigned char qdmsan_oob_read_sink;

int main(void) {
  const size_t n = 16;
  unsigned char *p = (unsigned char *)malloc(n);
  if (!p) { return 77; }

  for (size_t i = 0; i < n; ++i) { p[i] = (unsigned char)i; }
  qdmsan_oob_read_sink = ((volatile unsigned char *)p)[n];

  free(p);
  return 0;
}
