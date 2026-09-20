#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <time.h>

volatile unsigned long qdmsan_sink_ul;

int main(void) {
  struct timeval tv;
  struct timespec ts, res;
  struct timeb tb;
  struct tms tmsbuf;
  time_t t = time(0);
  clock_t clk = clock();
  gettimeofday(&tv, 0);
  clock_gettime(CLOCK_MONOTONIC, &ts);
  clock_getres(CLOCK_MONOTONIC, &res);
  ftime(&tb);
  times(&tmsbuf);
  qdmsan_sink_ul = (unsigned long)t ^ (unsigned long)tv.tv_usec ^
                   (unsigned long)ts.tv_nsec ^ (unsigned long)res.tv_nsec ^
                   (unsigned long)tb.millitm ^ (unsigned long)tmsbuf.tms_utime ^
                   (unsigned long)clk;
  if (qdmsan_sink_ul & 1) return 0;
  return 0;
}
