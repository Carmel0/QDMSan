#define _GNU_SOURCE
#include <stdint.h>
#include <sys/uio.h>
#include <unistd.h>

volatile uint64_t qdmsan_sink_u64;

int main(void) {
  uint64_t src = 0x123456789abcdef0ULL;
  uint64_t dst = 0;
  uint64_t src2 = 0;
  struct iovec local = {&dst, sizeof(dst)};
  struct iovec remote = {&src, sizeof(src)};
  if (process_vm_readv(getpid(), &local, 1, &remote, 1, 0) < 0) return 0;

  local.iov_base = &dst;
  remote.iov_base = &src2;
  if (process_vm_writev(getpid(), &local, 1, &remote, 1, 0) < 0) return 0;

  qdmsan_sink_u64 = dst ^ src2;
  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
