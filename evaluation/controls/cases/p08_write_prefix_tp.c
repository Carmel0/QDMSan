/* p08 write_prefix (TP)
 * Transfer: a 64-byte heap buffer with only bytes 0..15 written is handed to
 *           the write(2) system call.
 * Use:      the length argument covers 17 bytes: the initialized prefix plus
 *           buf[16], which was never written.
 */
#include <stdlib.h>
#include <unistd.h>

#define ESCAPE(p) __asm__ __volatile__("" : : "r"(p) : "memory")

volatile long sink;

int main(void) {
  unsigned char *buf = (unsigned char *)malloc(64);
  if (!buf) return 0;
  ESCAPE(buf);
  for (int i = 0; i < 16; i++) buf[i] = (unsigned char)('a' + i);
  ESCAPE(buf);

  ssize_t r = write(1, buf, 17);
  sink = (long)r;

  free(buf);
  return 0;
}
