#include <stdlib.h>

int main(void) {
  unsigned char *p = (unsigned char *)malloc(16);
  if (!p) { return 77; }

  p[0] = 0x31;
  free(p);
  ((volatile unsigned char *)p)[0] = 0x6b;
  __asm__ __volatile__("" ::: "memory");
  return 0;
}
