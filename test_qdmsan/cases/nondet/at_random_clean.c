#define _GNU_SOURCE
#include <stdint.h>
#include <sys/auxv.h>

volatile uint64_t qdmsan_sink_u64;

int main(void) {
  const unsigned char *p = (const unsigned char *)getauxval(AT_RANDOM);
  if (!p) return 0;
  for (int i = 0; i < 16; ++i) {
    qdmsan_sink_u64 = (qdmsan_sink_u64 << 5) ^ (qdmsan_sink_u64 >> 2) ^ p[i];
  }
  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
