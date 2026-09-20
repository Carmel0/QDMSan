/* p07 printf_uninit_tail (TP)
 * Transfer: a 32-byte stack buffer holding "hello" and a terminator at index
 *           31 (bytes 5..30 never written) is copied whole into a heap block.
 * Use:      the heap copy is printed with %s, so the uninitialized bytes that
 *           precede the terminator are scanned and printed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

int main(void) {
  char local[32];
  ESCAPE(local);
  memcpy(local, "hello", 5);
  local[31] = '\0';
  ESCAPE(local);

  char *s = (char *)malloc(32);
  if (!s) return 0;
  ESCAPE(s);
  memcpy(s, local, 32);
  ESCAPE(s);

  printf("[%s]\n", s);
  fflush(stdout);

  free(s);
  return 0;
}
