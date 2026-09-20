#include <stdlib.h>

volatile int qdmsan_sink_i32;

__attribute__((noinline)) static void set_sink_one(void) {
  qdmsan_sink_i32 = 1;
  __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline)) static void set_sink_two(void) {
  qdmsan_sink_i32 = 2;
  __asm__ __volatile__("" ::: "memory");
}

#define CHECK_BIT(mask)        \
  do {                        \
    if (*vp & (mask)) {        \
      set_sink_one();          \
    } else {                  \
      set_sink_two();          \
    }                         \
  } while (0)

int main(void) {
  unsigned char *p = (unsigned char *)malloc(1);
  volatile unsigned char *vp = p;
  /* Corresponding fill bytes differ in the low nibble. Use distinct branch
     sites so differences in separate bits cannot cancel at one loop site. */
  CHECK_BIT(0x01);
  CHECK_BIT(0x02);
  CHECK_BIT(0x04);
  CHECK_BIT(0x08);
  free(p);
  return 0;
}
