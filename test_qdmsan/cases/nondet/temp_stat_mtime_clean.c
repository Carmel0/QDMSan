#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
  char dir[] = "/tmp/qdmsan-temp-stat-XXXXXX";
  char path[256];

  if (!mkdtemp(dir)) return 1;
  if (snprintf(path, sizeof(path), "%s/input", dir) >= (int)sizeof(path)) {
    return 2;
  }

  FILE *fp = fopen(path, "w");
  if (!fp) return 3;
  fputs("seed\n", fp);
  if (fclose(fp) != 0) return 4;

  struct stat st;
  memset(&st, 0, sizeof(st));
  if (stat(path, &st) != 0) return 5;

  if ((st.st_mtim.tv_nsec & 0xffff) == 0x1234) return 6;
  if ((st.st_mtim.tv_sec & 0xffff) == 0x5678) return 7;
  return 0;
}
