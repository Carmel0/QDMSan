#include <string.h>

volatile char qdmsan_sink_char;

int main(void) {
  char src[4];
  char dst[4];
  src[0] = 'A';
  src[2] = '\0';
  strcpy(dst, src);
  qdmsan_sink_char = dst[0];
  return 0;
}
