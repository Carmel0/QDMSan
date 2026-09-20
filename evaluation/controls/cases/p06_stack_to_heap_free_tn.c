/* p06 stack_to_heap_free (TN)
 * Transfer: a 64-byte stack buffer with only bytes 0..7 written is copied into
 *           a heap block (56 uninitialized stack bytes move to the heap); the
 *           heap block is then freed.
 * Use:      only the initialized 8-byte prefix of the heap copy leaves the
 *           process through stdio (fwrite + fflush); the rest is freed unused.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

int main(void) {
  unsigned char tmp[64];
  ESCAPE(tmp);
  for (int i = 0; i < 8; i++) tmp[i] = (unsigned char)('A' + i);
  ESCAPE(tmp);

  unsigned char *h = (unsigned char *)malloc(64);
  if (!h) return 0;
  ESCAPE(h);
  memcpy(h, tmp, 64);
  ESCAPE(h);

  fwrite(h, 1, 8, stdout);
  fflush(stdout);

  free(h);
  return 0;
}
