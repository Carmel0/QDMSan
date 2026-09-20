/* p09 mask_zero (TN)
 * Transfer: an uninitialized heap word is loaded into a register and combined
 *           with a runtime mask (read from a volatile global so that the AND
 *           survives optimization).
 * Use:      the mask is 0, so (x & mask) is the constant 0 whatever x holds;
 *           only that constant decides the branch.
 */
#include <stdlib.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

volatile int sink;
volatile unsigned mask_value = 0x0u;

__attribute__((noinline)) static void path_a(void) {
  sink = 1;
  __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline)) static void path_b(void) {
  sink = 2;
  __asm__ __volatile__("" ::: "memory");
}

int main(void) {
  unsigned *x = (unsigned *)malloc(sizeof *x);
  if (!x) return 0;
  ESCAPE(x);

  unsigned m = mask_value;
  if ((*x & m) != 0) path_a(); else path_b();

  free(x);
  return 0;
}
