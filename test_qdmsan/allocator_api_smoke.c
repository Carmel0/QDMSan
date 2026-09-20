#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what) {
  fprintf(stderr, "allocator_api_smoke: %s\n", what);
  return 1;
}

static void *allocator_worker(void *opaque) {
  uintptr_t seed = (uintptr_t)opaque + 1;
  for (size_t i = 0; i < 4000; ++i) {
    size_t size = 1 + ((seed * 131 + i * 17) % 511);
    unsigned char *ptr = malloc(size);
    if (!ptr) return (void *)(uintptr_t)1;
    ptr[0] = (unsigned char)i;
    if (size > 1) ptr[size - 1] = (unsigned char)(i >> 3);
    if ((i & 7) == 0) {
      size_t grown = size + 37;
      ptr = realloc(ptr, grown);
      if (!ptr || ptr[0] != (unsigned char)i) return (void *)(uintptr_t)1;
    }
    free(ptr);
  }
  return NULL;
}

int main(void) {
  void *zero = malloc(0);
  if (!zero || malloc_usable_size(zero) != 0) return fail("malloc(0)");
  void (*volatile call_free)(void *) = free;
  call_free(zero);
  call_free(zero); /* Must remain harmless while the object is quarantined. */

  unsigned char *plain = malloc(17);
  if (!plain || (uintptr_t)plain % _Alignof(max_align_t) ||
      malloc_usable_size(plain) != 17) {
    return fail("malloc alignment/usable size");
  }
  for (size_t i = 0; i < 17; ++i) plain[i] = (unsigned char)(i + 1);
  plain = realloc(plain, 37);
  if (!plain || malloc_usable_size(plain) != 37) return fail("realloc grow");
  for (size_t i = 0; i < 17; ++i) {
    if (plain[i] != (unsigned char)(i + 1)) return fail("realloc copy");
  }
  if (realloc(plain, 0) != NULL) return fail("realloc(ptr, 0)");

  unsigned int *cleared = calloc(23, sizeof(*cleared));
  if (!cleared || malloc_usable_size(cleared) != 23 * sizeof(*cleared)) {
    return fail("calloc size");
  }
  for (size_t i = 0; i < 23; ++i) {
    if (cleared[i] != 0) return fail("calloc initialization");
  }
  free(cleared);

  void *aligned = NULL;
  errno = EDOM;
  if (posix_memalign(&aligned, 4096, 33) || !aligned ||
      (uintptr_t)aligned % 4096 || malloc_usable_size(aligned) != 33 ||
      errno != EDOM) {
    return fail("posix_memalign");
  }
  free(aligned);

  aligned = (void *)(uintptr_t)0x1234;
  errno = ERANGE;
  if (posix_memalign(&aligned, 3, 8) != EINVAL ||
      aligned != (void *)(uintptr_t)0x1234 || errno != ERANGE) {
    return fail("posix_memalign invalid alignment");
  }

  aligned = aligned_alloc(256, 512);
  if (!aligned || (uintptr_t)aligned % 256 ||
      malloc_usable_size(aligned) != 512) {
    return fail("aligned_alloc");
  }
  free(aligned);

  aligned = memalign(512, 29);
  if (!aligned || (uintptr_t)aligned % 512 ||
      malloc_usable_size(aligned) != 29) {
    return fail("memalign");
  }
  free(aligned);

  errno = 0;
  if (aligned_alloc(64, 65) != NULL || errno != EINVAL) {
    return fail("aligned_alloc invalid size");
  }

  long page = sysconf(_SC_PAGESIZE);
  void *page_ptr = valloc(19);
  if (!page_ptr || page <= 0 || (uintptr_t)page_ptr % (size_t)page) {
    return fail("valloc");
  }
  free(page_ptr);
  page_ptr = pvalloc(19);
  if (!page_ptr || (uintptr_t)page_ptr % (size_t)page ||
      malloc_usable_size(page_ptr) != (size_t)page) {
    return fail("pvalloc");
  }
  free(page_ptr);

  errno = 0;
  volatile size_t huge_nmemb = SIZE_MAX;
  if (calloc(huge_nmemb, 2) != NULL || errno != ENOMEM) {
    return fail("calloc overflow");
  }
  errno = 0;
  if (malloc(huge_nmemb) != NULL || errno != ENOMEM) {
    return fail("malloc redzone overflow");
  }

  unsigned char *unchanged = malloc(9);
  if (!unchanged) return fail("realloc failure setup");
  memcpy(unchanged, "preserve", 9);
  errno = 0;
  if (realloc(unchanged, huge_nmemb) != NULL || errno != ENOMEM ||
      memcmp(unchanged, "preserve", 9)) {
    return fail("realloc failure preservation");
  }
  errno = 0;
  if (reallocarray(unchanged, huge_nmemb, 2) != NULL || errno != ENOMEM ||
      memcmp(unchanged, "preserve", 9)) {
    return fail("reallocarray overflow preservation");
  }
  free(unchanged);

  /* With AFL_QDMSAN_QUARANTINE_MB=1 this forces repeated FIFO eviction and
     exercises removal of retired metadata/regions. */
  for (size_t i = 0; i < 20000; ++i) {
    unsigned char *item = malloc(193 + i % 31);
    if (!item) return fail("quarantine stress allocation");
    item[0] = (unsigned char)i;
    item[192 + i % 31] = (unsigned char)(i >> 8);
    free(item);
  }

  pthread_t threads[6];
  for (uintptr_t i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
    if (pthread_create(&threads[i], NULL, allocator_worker, (void *)i)) {
      return fail("pthread_create");
    }
  }
  for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
    void *result = NULL;
    if (pthread_join(threads[i], &result) || result) {
      return fail("concurrent allocator stress");
    }
  }

  void *libc = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
  void *(*libc_malloc)(size_t) =
      libc ? (void *(*)(size_t))dlsym(libc, "malloc") : NULL;
  if (!libc_malloc) return fail("resolve foreign allocator");
  void *foreign = libc_malloc(71);
  if (!foreign) return fail("foreign allocation");
  free(foreign); /* Unknown allocations must be forwarded, not quarantined. */
  dlclose(libc);

  puts("allocator_api_smoke: ok");
  return 0;
}
