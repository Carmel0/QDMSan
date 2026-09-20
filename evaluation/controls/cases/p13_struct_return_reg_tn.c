/* p13 struct_return_reg (TN)
 * Transfer: a callee builds an 8-byte struct in its stack frame (3 padding
 *           bytes never written) and returns it by value, so the padding
 *           travels through RAX; the caller stores it into a heap object.
 * Use:      only the named fields of the stored copy decide a branch.
 */
#include <stdint.h>
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

struct pair {
  uint8_t tag;  /* offset 0; bytes 1..3 are padding */
  uint32_t len; /* offset 4; sizeof(struct pair) = 8 */
};

__attribute__((noinline)) static struct pair make_pair(void) {
  struct pair p;
  ESCAPE(&p);
  p.tag = 9;
  p.len = 300;
  ESCAPE(&p);
  return p;
}

int main(void) {
  struct pair r = make_pair();
  struct pair *h = (struct pair *)malloc(sizeof *h);
  if (!h) return 0;
  ESCAPE(h);
  *h = r;
  ESCAPE(h);
  const unsigned char *raw = (const unsigned char *)h;
  (void)raw;

  if (h->tag == 9 && h->len == 300) path_a(); else path_b();

  free(h);
  return 0;
}
