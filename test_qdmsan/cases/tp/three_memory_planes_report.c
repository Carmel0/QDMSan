#include <stddef.h>
#include <stdlib.h>

volatile unsigned int qdmsan_three_plane_sink;

int main(void) {
  unsigned char *uninit = (unsigned char *)malloc(1);
  unsigned char *oob = (unsigned char *)malloc(16);
  unsigned char *uaf = (unsigned char *)malloc(16);
  if (!uninit || !oob || !uaf) { return 77; }

  qdmsan_three_plane_sink +=
      (*(volatile unsigned char *)uninit == (unsigned char)0x7d);

  for (size_t i = 0; i < 16; ++i) { oob[i] = (unsigned char)i; }
  qdmsan_three_plane_sink += ((volatile unsigned char *)oob)[16];

  uaf[0] = 0x44;
  free(uaf);
  qdmsan_three_plane_sink += ((volatile unsigned char *)uaf)[0];

  free(oob);
  free(uninit);
  return 0;
}
