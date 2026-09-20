#include <stdlib.h>

volatile int qdmsan_sink_i32;

int main(void) {
  unsigned char *p = (unsigned char *)malloc(1);
  volatile unsigned char *vp = p;
  int same_result = (vp[0] == vp[0]);
  qdmsan_sink_i32 = same_result;
  free(p);
  return 0;
}
