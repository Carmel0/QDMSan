#define _GNU_SOURCE
#include <stdint.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

volatile uint64_t qdmsan_sink_u64;

int main(void) {
  uint64_t x = 0;
  if (syscall(SYS_getrandom, &x, sizeof(x), 0) != (ssize_t)sizeof(x)) {
    return 0;
  }
  qdmsan_sink_u64 = x;
  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
