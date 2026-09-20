#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>

volatile unsigned int qdmsan_allocator_api_sink;

int main(void) {
  unsigned char *p = (unsigned char *)malloc(17);
  if (!p) { return 77; }
  for (size_t i = 0; i < 17; ++i) { p[i] = (unsigned char)(i + 1); }
  if (malloc_usable_size(p) < 17) { return 10; }

  unsigned char *grown = (unsigned char *)realloc(p, 257);
  if (!grown) {
    free(p);
    return 77;
  }
  for (size_t i = 0; i < 17; ++i) {
    qdmsan_allocator_api_sink += grown[i];
  }
  for (size_t i = 17; i < 257; ++i) { grown[i] = (unsigned char)i; }
  free(grown);

  void *aligned = NULL;
  if (posix_memalign(&aligned, 128, 33) != 0 || !aligned) { return 11; }
  if (((uintptr_t)aligned & 127u) != 0) { return 12; }
  for (size_t i = 0; i < 33; ++i) {
    ((unsigned char *)aligned)[i] = (unsigned char)(i ^ 0x5a);
  }
  free(aligned);

  unsigned int *zeros = (unsigned int *)calloc(8, sizeof(*zeros));
  if (!zeros) { return 77; }
  for (size_t i = 0; i < 8; ++i) {
    qdmsan_allocator_api_sink += zeros[i];
  }
  free(zeros);
  return 0;
}
