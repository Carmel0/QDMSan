#include <stdlib.h>

volatile int qdmsan_sink_i32;

int main(void) {
  int *p = (int *)calloc(1, sizeof(*p));
  if (*p) {
    qdmsan_sink_i32 = 1;
  } else {
    qdmsan_sink_i32 = 2;
  }
  free(p);
  return 0;
}
