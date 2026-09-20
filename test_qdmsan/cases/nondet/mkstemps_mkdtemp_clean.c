#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static int use_template_bytes(const char *path) {
  unsigned acc = 0;
  for (int i = 0; path[i]; ++i) {
    acc = acc * 131u + (unsigned char)path[i];
  }
  return acc == 0x12345678u;
}

int main(void) {
  char tmpl1[] = "/tmp/qdmsanXXXXXX.flac";
  int fd1 = mkstemps(tmpl1, 5);
  if (fd1 < 0) return 1;
  close(fd1);
  int r1 = use_template_bytes(tmpl1);
  unlink(tmpl1);

  char tmpl2[] = "/tmp/qdmsanXXXXXX.tmp";
  int fd2 = mkostemps(tmpl2, 4, O_CLOEXEC);
  if (fd2 < 0) return 2;
  close(fd2);
  int r2 = use_template_bytes(tmpl2);
  unlink(tmpl2);

  char tmpl3[] = "/tmp/qdmsanXXXXXX.dir";
  char *dir = mkdtemp(tmpl3);
  if (!dir) return 3;
  int r3 = use_template_bytes(tmpl3);
  rmdir(tmpl3);

  return r1 | r2 | r3;
}
