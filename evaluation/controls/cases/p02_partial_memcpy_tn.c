/* p02 partial_memcpy (TN)
 * Transfer: libc memcpy (runtime length, so it stays a call at -O2) copies a
 *           64-byte heap buffer of which only the first 16 bytes were written.
 * Use:      only the initialized 16-byte prefix of the copy is used as table
 *           indices (memory-address consumption).
 */
#include <stdlib.h>
#include <string.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

#define N 64
#define K 16

volatile unsigned sink;
volatile size_t copy_len = N;
volatile unsigned char lut[256];

int main(void) {
  unsigned char *src = (unsigned char *)malloc(N);
  unsigned char *dst = (unsigned char *)malloc(N);
  if (!src || !dst) return 0;
  ESCAPE(src);
  ESCAPE(dst);
  for (int i = 0; i < K; i++) src[i] = (unsigned char)(i * 7 + 1);
  ESCAPE(src);

  memcpy(dst, src, copy_len);
  ESCAPE(dst);

  unsigned acc = 0;
  for (int i = 0; i < K; i++) acc += lut[dst[i]];
  sink = acc;

  free(dst);
  free(src);
  return 0;
}
