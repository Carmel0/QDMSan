/* p03 realloc_grow (TP)
 * Transfer: a 16-byte heap block with only bytes 0..7 written is grown to
 *           4096 bytes by realloc; the copy carries the 8 uninitialized old
 *           bytes and the new tail is uninitialized as well.
 * Use:      old bytes 0..8 decide branches; q[8] is an uninitialized old byte
 *           carried by the realloc copy.
 */
#include <stdlib.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

volatile int sink;

__attribute__((noinline)) static void path_a(void) {
  sink = 1;
  __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline)) static void path_b(void) {
  sink = 2;
  __asm__ __volatile__("" ::: "memory");
}

int main(void) {
  unsigned char *p = (unsigned char *)malloc(16);
  if (!p) return 0;
  ESCAPE(p);
  for (int i = 0; i < 8; i++) p[i] = (unsigned char)('a' + i);
  ESCAPE(p);

  unsigned char *q = (unsigned char *)realloc(p, 4096);
  if (!q) { free(p); return 0; }
  ESCAPE(q);

  for (int i = 0; i < 9; i++) {
    if (q[i] == 'c') path_a(); else path_b();
  }

  free(q);
  return 0;
}
