#define _GNU_SOURCE
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

volatile uint64_t qdmsan_sink_u64;

int main(void) {
  struct timeval tv;
  struct timespec ts;
  struct tms tmsbuf;
  long t = 0;

#ifdef SYS_time
  t = syscall(SYS_time, 0);
#endif
  if (syscall(SYS_gettimeofday, &tv, 0) < 0) return 0;
  if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) < 0) return 0;
  (void)syscall(SYS_times, &tmsbuf);

  qdmsan_sink_u64 = (uint64_t)t ^ (uint64_t)tv.tv_sec ^
                    (uint64_t)tv.tv_usec ^ (uint64_t)ts.tv_sec ^
                    (uint64_t)ts.tv_nsec ^ (uint64_t)tmsbuf.tms_utime;
  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
