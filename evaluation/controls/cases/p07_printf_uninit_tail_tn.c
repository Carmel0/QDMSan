/* p07 printf_uninit_tail (TN)
 * Transfer: a 32-byte stack buffer holding "hello" and a terminator at index 5
 *           (bytes 6..31 never written) is copied whole into a heap block.
 * Use:      the heap copy is printed with %s, so only bytes up to the
 *           terminator are consumed; the uninitialized tail is not.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

int main(void) {
  char local[32];
  ESCAPE(local);
  memcpy(local, "hello", 5);
  local[5] = '\0';
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
