#include <stddef.h>
#include <stdlib.h>

volatile unsigned int qdmsan_in_bounds_sink;

int main(void) {
  const size_t n = 32;
  unsigned char *p = (unsigned char *)malloc(n);
  if (!p) { return 77; }

  for (size_t i = 0; i < n; ++i) { p[i] = (unsigned char)(i + 3); }
  for (size_t i = 0; i < n; ++i) { qdmsan_in_bounds_sink += p[i]; }

  free(p);
  return 0;
}
