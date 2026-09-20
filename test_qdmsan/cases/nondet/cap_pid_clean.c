#define _GNU_SOURCE
#include <linux/capability.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

volatile uint64_t qdmsan_sink_u64;

int main(void) {
  struct __user_cap_header_struct hdr;
  struct __user_cap_data_struct data[2];

  hdr.version = _LINUX_CAPABILITY_VERSION_3;
  hdr.pid = (int)getpid();
  if (syscall(SYS_capget, &hdr, data) < 0) return 0;
  qdmsan_sink_u64 = (uint64_t)(unsigned)hdr.pid ^
                    (uint64_t)data[0].effective ^
                    ((uint64_t)data[1].effective << 1);
  if (qdmsan_sink_u64 & 1) return 0;
  return 0;
}
