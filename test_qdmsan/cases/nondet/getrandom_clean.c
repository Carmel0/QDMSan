#include <stdint.h>
#include <sys/random.h>

volatile uint64_t qdmsan_sink_u64;

int main(void) {
  uint64_t a = 0;
  unsigned char b[8];
  if (getrandom(&a, sizeof(a), 0) != (ssize_t)sizeof(a)) return 0;
  if (getentropy(b, sizeof(b)) != 0) return 0;
  qdmsan_sink_u64 = a ^ (uint64_t)b[0] ^ ((uint64_t)b[7] << 8);
  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
