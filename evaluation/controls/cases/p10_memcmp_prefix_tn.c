/* p10 memcmp_prefix (TN, POLICY-DEPENDENT)
 * Transfer: two 32-byte heap buffers with only bytes 0..3 written are passed
 *           whole to libc memcmp (runtime length, so it stays a call at -O2).
 * Use:      the buffers first differ at initialized index 3 ('D' vs 'E'), so
 *           the memcmp result is decided by initialized bytes; bytes 4..31 are
 *           never needed. A checker that treats every byte in [0, n) as
 *           consumed (strict memcmp policy) may report this case.
 */
#include <stdlib.h>
#include <string.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

volatile int sink;
volatile size_t cmp_len = 32;

__attribute__((noinline)) static void path_a(void) {
  sink = 1;
  __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline)) static void path_b(void) {
  sink = 2;
  __asm__ __volatile__("" ::: "memory");
}

int main(void) {
  unsigned char *a = (unsigned char *)malloc(32);
  unsigned char *b = (unsigned char *)malloc(32);
  if (!a || !b) return 0;
  ESCAPE(a);
  ESCAPE(b);
  memcpy(a, "ABCD", 4);
  memcpy(b, "ABCE", 4);
  ESCAPE(a);
  ESCAPE(b);

  if (memcmp(a, b, cmp_len) < 0) path_a(); else path_b();

  free(b);
  free(a);
  return 0;
}
