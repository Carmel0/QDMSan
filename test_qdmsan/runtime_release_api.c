#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define CHECK(label, expr, expected, error) do { \
  errno = 0; \
  long result = (expr); \
  int saved_errno = errno; \
  printf("%s %ld %d\n", label, result, saved_errno); \
  if (result != (expected) || (result < 0 && saved_errno != (error))) \
    failed = 1; \
} while (0)

int main(int argc, char **argv) {
  (void)argv;
  int failed = 0;
  unsigned char bytes[257];
  struct timespec ts;
  CHECK("getrandom-flags", getrandom(bytes, 1, 0x80000000u), -1, EINVAL);
  CHECK("getrandom-conflict", getrandom(bytes, 1, GRND_RANDOM | GRND_INSECURE),
        -1, EINVAL);
  CHECK("getrandom-empty", getrandom(NULL, 0, 0), 0, 0);
  CHECK("getrandom-valid", getrandom(bytes, 16, 0), 16, 0);
  CHECK("sysrandom-flags", syscall(SYS_getrandom, bytes, 1, 0x80000000u),
        -1, EINVAL);
  CHECK("sysrandom-empty", syscall(SYS_getrandom, NULL, 0, 0), 0, 0);
  CHECK("sysrandom-valid", syscall(SYS_getrandom, bytes, 16, 0), 16, 0);
  CHECK("getentropy-257", getentropy(bytes, 257), -1, EIO);
  CHECK("getentropy-256", getentropy(bytes, 256), 0, 0);
  CHECK("getentropy-empty", getentropy(NULL, 0), 0, 0);
  CHECK("clock-invalid", clock_gettime(123456, &ts), -1, EINVAL);
  CHECK("clockres-invalid", clock_getres(123456, &ts), -1, EINVAL);
  CHECK("clockres-null", clock_getres(CLOCK_MONOTONIC, NULL), 0, 0);
  CHECK("clock-valid", clock_gettime(CLOCK_MONOTONIC, &ts), 0, 0);
  CHECK("sysclock-invalid", syscall(SYS_clock_gettime, 123456, &ts), -1, EINVAL);
  CHECK("sysclockres-invalid", syscall(SYS_clock_getres, 123456, &ts), -1, EINVAL);
  CHECK("sysclockres-null", syscall(SYS_clock_getres, CLOCK_MONOTONIC, NULL), 0, 0);
  CHECK("sysclockres-fault", syscall(SYS_clock_getres, CLOCK_MONOTONIC, (void *)-1),
        -1, EFAULT);
  if (argc > 1) {
    for (unsigned i = 0; i < 16; ++i) printf("%02x", bytes[i]);
    printf(" %ld %ld\n", (long)ts.tv_sec, ts.tv_nsec);
  }
  return failed;
}
