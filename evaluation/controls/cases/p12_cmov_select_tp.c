/* p12 cmov_select (TP)
 * Transfer: an initialized heap int and an uninitialized heap int are both
 *           loaded into registers; a select (branchless when optimized)
 *           picks one of them under an initialized condition.
 * Use:      the condition picks the uninitialized value, and the selected
 *           value decides the branch.
 */
#include <stdlib.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

volatile int sink;
volatile int pick_init = 0;

__attribute__((noinline)) static void path_a(void) {
  sink = 1;
  __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline)) static void path_b(void) {
  sink = 2;
  __asm__ __volatile__("" ::: "memory");
}

int main(void) {
  int *dp = (int *)malloc(sizeof *dp);
  int *up = (int *)malloc(sizeof *up);
  if (!dp || !up) return 0;
  ESCAPE(dp);
  ESCAPE(up);
  *dp = 7;
  ESCAPE(dp);

  int a = *dp;
  int b = *up;
  int c = pick_init;
  int v = c ? a : b;
  if (v == 7) path_a(); else path_b();

  free(up);
  free(dp);
  return 0;
}
