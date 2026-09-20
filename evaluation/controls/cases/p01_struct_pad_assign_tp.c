/* p01 struct_pad_assign (TP)
 * Transfer: a stack struct whose padding bytes were never written is copied
 *           into a heap object by struct assignment (padding travels along).
 * Use:      the named fields AND padding byte 1 of the copy decide a branch.
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

struct rec {
  uint8_t tag;  /* offset 0; bytes 1..3 are padding  */
  uint32_t len; /* offset 4                          */
  uint16_t id;  /* offset 8; bytes 10..15 are padding */
  uint64_t val; /* offset 16; sizeof(struct rec) = 24 */
};

int main(void) {
  struct rec local;
  ESCAPE(&local);
  local.tag = 3;
  local.len = 40;
  local.id = 7;
  local.val = 0x1122334455667788ULL;

  struct rec *copy = (struct rec *)malloc(sizeof *copy);
  if (!copy) return 0;
  ESCAPE(copy);
  *copy = local;
  ESCAPE(copy);
  const unsigned char *raw = (const unsigned char *)copy;
  (void)raw;

  if (copy->tag == 3 && copy->len == 40 && copy->id == 7 && raw[1] == 0x5a) path_a(); else path_b();

  free(copy);
  return 0;
}
