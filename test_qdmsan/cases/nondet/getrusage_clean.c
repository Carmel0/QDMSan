#define _GNU_SOURCE
#include <stdint.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

static int consume_rusage(struct rusage *usage) {
  uint64_t acc = 0;
  acc += (uint64_t)usage->ru_utime.tv_sec;
  acc += (uint64_t)usage->ru_utime.tv_usec;
  acc += (uint64_t)usage->ru_stime.tv_sec;
  acc += (uint64_t)usage->ru_stime.tv_usec;
  return acc == 0x12345678ULL;
}

int main(void) {
  struct rusage usage;

  for (int i = 0; i < 32; ++i) {
    if (getrusage(RUSAGE_SELF, &usage) != 0) return 1;
    if (consume_rusage(&usage)) return 2;
  }

  for (int i = 0; i < 32; ++i) {
    if (syscall(SYS_getrusage, RUSAGE_SELF, &usage) != 0) return 3;
    if (consume_rusage(&usage)) return 4;
  }

  return 0;
}
