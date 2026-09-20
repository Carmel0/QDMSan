/* p10 memcmp_prefix (TP, POLICY-DEPENDENT pair)
 * Transfer: two 32-byte heap buffers with only bytes 0..3 written are passed
 *           whole to libc memcmp (runtime length, so it stays a call at -O2).
 * Use:      bytes 0..3 are equal ("ABCD" vs "ABCD"), so the first difference,
 *           and hence the memcmp result, is decided by uninitialized bytes.
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
  memcpy(b, "ABCD", 4);
  ESCAPE(a);
  ESCAPE(b);

  if (memcmp(a, b, cmp_len) < 0) path_a(); else path_b();

  free(b);
  free(a);
  return 0;
}
