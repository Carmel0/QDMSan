#include <stddef.h>
#include <stdlib.h>

int main(void) {
  const size_t n = 16;
  unsigned char *p = (unsigned char *)malloc(n);
  if (!p) { return 77; }

  for (size_t i = 0; i < n; ++i) { p[i] = (unsigned char)(i + 1); }
  ((volatile unsigned char *)p)[n] = 0x5a;
  __asm__ __volatile__("" ::: "memory");

  free(p);
  return 0;
}
