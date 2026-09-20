#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  char dir[] = "/tmp/qdmsan-temp-unlink-XXXXXX";
  char path1[256];
  char path2[256];

  if (!mkdtemp(dir)) return 1;
  if (snprintf(path1, sizeof(path1), "%s/missing-a", dir) >=
      (int)sizeof(path1)) {
    return 2;
  }
  if (snprintf(path2, sizeof(path2), "%s/missing-b", dir) >=
      (int)sizeof(path2)) {
    return 3;
  }

  (void)unlink(path1);
  (void)remove(path1);
  (void)rmdir(path1);
  (void)rename(path1, path2);

  int fd = openat(AT_FDCWD, path1, O_CREAT | O_EXCL | O_RDWR, 0600);
  if (fd < 0) return 4;
  close(fd);
  unlink(path1);

  return 0;
}
