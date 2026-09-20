#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { THREADS = 4, ITERATIONS = 3000 };

static void *worker(void *opaque) {
  uintptr_t id = (uintptr_t)opaque;
  for (size_t i = 0; i < ITERATIONS; ++i) {
    size_t n = 64 + ((i * 131 + id * 17) & 4095u);
    unsigned char value = (unsigned char)(i ^ id);
    unsigned char *p = (unsigned char *)malloc(n);
    if (!p) { return (void *)1; }
    memset(p, value, n);
    if (p[0] != value || p[n - 1] != value) { return (void *)2; }

    if ((i & 7u) == 0) {
      size_t grown_n = n + 257;
      unsigned char *grown = (unsigned char *)realloc(p, grown_n);
      if (!grown) {
        free(p);
        return (void *)3;
      }
      if (grown[0] != value || grown[n - 1] != value) { return (void *)4; }
      memset(grown + n, value, grown_n - n);
      p = grown;
    }
    free(p);
  }
  return NULL;
}

int main(void) {
  pthread_t threads[THREADS];
  for (uintptr_t i = 0; i < THREADS; ++i) {
    if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) { return 10; }
  }
  for (size_t i = 0; i < THREADS; ++i) {
    void *result = NULL;
    if (pthread_join(threads[i], &result) != 0 || result) { return 11; }
  }
  return 0;
}
