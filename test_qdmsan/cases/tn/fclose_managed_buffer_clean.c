#include <stdio.h>

int main(void) {
  FILE *stream = tmpfile();
  if (!stream) return 0;

  for (unsigned i = 0; i < 4096; ++i) {
    if (fputc((int)('A' + (i % 26)), stream) == EOF) {
      fclose(stream);
      return 0;
    }
  }
  rewind(stream);

  unsigned long sum = 0;
  for (unsigned i = 0; i < 4096; ++i) {
    int c = fgetc(stream);
    if (c == EOF) break;
    sum += (unsigned)c;
  }

  if (fclose(stream) != 0) return 0;
  return sum == 0;
}
