#include <stdint.h>

volatile uint64_t qdmsan_sink_u64;

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *a, uint32_t *b,
                  uint32_t *c, uint32_t *d) {
  __asm__ volatile("cpuid"
                   : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                   : "a"(leaf), "c"(subleaf));
}

int main(void) {
#if defined(__x86_64__) || defined(__i386__)
  uint32_t a = 0, b = 0, c = 0, d = 0;
  unsigned int lo = 0, hi = 0, aux = 0;
  uint64_t x = 0, y = 0;
  unsigned char ok = 0;

  __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
  qdmsan_sink_u64 = ((uint64_t)hi << 32) | lo;

  cpuid(0x80000001u, 0, &a, &b, &c, &d);
  if (d & (1u << 27)) {
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    qdmsan_sink_u64 ^= ((uint64_t)hi << 32) | lo | aux;
  }

  cpuid(1, 0, &a, &b, &c, &d);
  if (c & (1u << 30)) {
#if defined(__x86_64__)
    __asm__ volatile(".byte 0x48,0x0f,0xc7,0xf0; setc %1"
                     : "=a"(x), "=qm"(ok)
                     :
                     : "cc");
#else
    __asm__ volatile(".byte 0x0f,0xc7,0xf0; setc %1"
                     : "=a"(x), "=qm"(ok)
                     :
                     : "cc");
#endif
    qdmsan_sink_u64 ^= x ^ ok;
  }

  cpuid(7, 0, &a, &b, &c, &d);
  if (b & (1u << 18)) {
#if defined(__x86_64__)
    __asm__ volatile(".byte 0x48,0x0f,0xc7,0xf8; setc %1"
                     : "=a"(y), "=qm"(ok)
                     :
                     : "cc");
#else
    __asm__ volatile(".byte 0x0f,0xc7,0xf8; setc %1"
                     : "=a"(y), "=qm"(ok)
                     :
                     : "cc");
#endif
    qdmsan_sink_u64 ^= y ^ ok;
  }

  if (qdmsan_sink_u64 & 1) return 0;
#endif
  return 0;
}
