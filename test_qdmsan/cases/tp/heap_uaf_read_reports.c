#include <stdlib.h>

volatile unsigned char qdmsan_uaf_read_sink;

int main(void) {
  unsigned char *p = (unsigned char *)malloc(16);
  if (!p) { return 77; }

  p[0] = 0x31;
  free(p);
  qdmsan_uaf_read_sink = ((volatile unsigned char *)p)[0];
  return 0;
}
