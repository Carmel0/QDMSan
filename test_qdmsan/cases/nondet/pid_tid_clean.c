#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

volatile long qdmsan_sink_l;

int main(void) {
  long pid = (long)getpid();
  long ppid = (long)getppid();
  long tid = syscall(SYS_gettid);
  qdmsan_sink_l = pid ^ (ppid << 1) ^ (tid << 2);
  if (qdmsan_sink_l & 1) return 0;
  return 0;
}
