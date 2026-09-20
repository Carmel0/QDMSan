/* p11 partial_word (TN)
 * Transfer: a 4-byte heap object with only byte 0 written is moved as one
 *           32-bit word (load into a register, store into a second heap
 *           object), so 3 uninitialized bytes travel inside the word.
 * Use:      the copy is masked with the constant 0xff, so only the
 *           initialized low byte decides the branch.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
  unsigned char *src = (unsigned char *)malloc(4);
  uint32_t *dst = (uint32_t *)malloc(sizeof *dst);
  if (!src || !dst) return 0;
  ESCAPE(src);
  ESCAPE(dst);
  src[0] = 'A';
  ESCAPE(src);

  uint32_t w;
  memcpy(&w, src, 4);
  *dst = w;
  ESCAPE(dst);

  if ((*dst & 0xffu) == 'A') path_a(); else path_b();

  free(dst);
  free(src);
  return 0;
}
