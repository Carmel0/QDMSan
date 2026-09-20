#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <sys/uio.h>
#include <unistd.h>

volatile uint64_t qdmsan_sink_u64;

static void mix_bytes(const unsigned char *p, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    qdmsan_sink_u64 = (qdmsan_sink_u64 << 5) ^ (qdmsan_sink_u64 >> 2) ^ p[i];
  }
}

int main(void) {
  unsigned char a[8] = {0}, b[8] = {0}, c[8] = {0}, d[8] = {0}, e[8] = {0};
  struct iovec iov[2] = {{b, sizeof(b)}, {c, sizeof(c)}};

  int fd = openat(AT_FDCWD, "/dev/urandom", O_RDONLY);
  if (fd < 0) return 0;
  if (read(fd, a, sizeof(a)) != (ssize_t)sizeof(a)) return 0;

  int fd_dup = dup(fd);
  if (fd_dup < 0) return 0;
  if (readv(fd_dup, iov, 2) != (ssize_t)(sizeof(b) + sizeof(c))) return 0;

  int fd_dup2 = dup2(fd, fd_dup + 1);
  if (fd_dup2 < 0) return 0;
  if (pread(fd_dup2, d, sizeof(d), 0) != (ssize_t)sizeof(d)) return 0;

  int fd_fcntl = fcntl(fd, F_DUPFD, fd_dup2 + 1);
  if (fd_fcntl < 0) return 0;
  struct iovec piov[1] = {{e, sizeof(e)}};
  if (preadv(fd_fcntl, piov, 1, 0) != (ssize_t)sizeof(e)) return 0;

  mix_bytes(a, sizeof(a));
  mix_bytes(b, sizeof(b));
  mix_bytes(c, sizeof(c));
  mix_bytes(d, sizeof(d));
  mix_bytes(e, sizeof(e));
  close(fd_fcntl);
  close(fd_dup2);
  close(fd_dup);
  close(fd);
  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
