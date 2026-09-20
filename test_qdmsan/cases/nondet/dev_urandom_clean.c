#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

volatile uint64_t qdmsan_sink_u64;

int main(void) {
  uint64_t x = 0;
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) return 0;
  (void)read(fd, &x, sizeof(x));
  close(fd);
  qdmsan_sink_u64 = x;
  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
