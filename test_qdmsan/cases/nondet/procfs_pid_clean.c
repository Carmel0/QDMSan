#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

volatile uint64_t qdmsan_sink_u64;

int main(void) {
  char path[128];
  char linkbuf[256];
  struct stat st;
  pid_t pid = getpid();

  snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) return 0;
  if (fstat(fd, &st) == 0) qdmsan_sink_u64 ^= (uint64_t)st.st_size;
  close(fd);

  snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
  ssize_t n = readlink(path, linkbuf, sizeof(linkbuf));
  if (n > 0) qdmsan_sink_u64 ^= (uint64_t)n;
  if (stat(path, &st) == 0) qdmsan_sink_u64 ^= (uint64_t)st.st_ino;

  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
