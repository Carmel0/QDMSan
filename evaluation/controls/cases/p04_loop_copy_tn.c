/* p04 loop_copy (TN)
 * Transfer: an element-wise loop copies a 16-int stack array of which only
 *           elements 0..3 were written (12 uninitialized ints move).
 * Use:      only copied elements 0..3 are compared; the hit count decides a
 *           branch.
 */
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
  int src[16];
  int dst[16];
  ESCAPE(src);
  ESCAPE(dst);
  for (int i = 0; i < 4; i++) src[i] = 3 * i + 1;
  ESCAPE(src);

  for (int i = 0; i < 16; i++) dst[i] = src[i];
  ESCAPE(dst);

  int hits = 0;
  for (int i = 0; i < 4; i++) {
    if (dst[i] == 3 * i + 1) hits++;
  }
  if (hits == 4) path_a(); else path_b();
  return 0;
}
