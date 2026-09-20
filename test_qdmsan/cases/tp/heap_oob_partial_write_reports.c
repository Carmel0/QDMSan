#include <stdint.h>
#include <stdlib.h>

volatile size_t qdmsan_partial_offset = 14;

int main(void) {
  unsigned char *p = (unsigned char *)malloc(16);
  if (!p) { return 77; }
  for (size_t i = 0; i < 16; ++i) { p[i] = (unsigned char)i; }

  *(volatile uint32_t *)(void *)(p + qdmsan_partial_offset) = UINT32_C(0xa5a55a5a);
  __asm__ __volatile__("" ::: "memory");
  free(p);
  return 0;
}
