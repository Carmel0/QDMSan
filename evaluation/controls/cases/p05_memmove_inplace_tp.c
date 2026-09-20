/* p05 memmove_inplace (TP)
 * Transfer: an overlapping libc memmove (runtime length) inside one 64-byte
 *           heap buffer whose bytes 0..7 were written: b[4..11] receive the
 *           old initialized bytes, b[12..35] receive old uninitialized bytes.
 * Use:      b[12] (= old b[8], uninitialized) bounds a loop that calls a
 *           function per iteration (branch consumption).
 */
#include <stdlib.h>
#include <string.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

volatile int sink;
volatile size_t move_len = 32;

__attribute__((noinline)) static void step(void) {
  sink = sink + 1;
  __asm__ __volatile__("" ::: "memory");
}

int main(void) {
  unsigned char *b = (unsigned char *)malloc(64);
  if (!b) return 0;
  ESCAPE(b);
  for (int i = 0; i < 8; i++) b[i] = (unsigned char)(i + 1);
  ESCAPE(b);

  memmove(b + 4, b, move_len);
  ESCAPE(b);

  unsigned bound = b[12];
  for (unsigned j = 0; j < bound; j++) step();

  free(b);
  return 0;
}
