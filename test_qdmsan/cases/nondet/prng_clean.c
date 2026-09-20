#include <stdlib.h>
#include <stdint.h>
#include <string.h>

volatile long qdmsan_sink_l;

int main(void) {
  struct random_data rd;
  char state[64];
  int32_t rr = 0;
  double dr = 0.0;
  long lr = 0;
  long mr = 0;
  struct drand48_data d48;
  unsigned int rand_r_seed = 7;
  unsigned short seedv[3] = {1, 2, 3};

  memset(&rd, 0, sizeof(rd));
  memset(state, 0, sizeof(state));
  memset(&d48, 0, sizeof(d48));

  srand(123);
  srandom(456);
  srand48(789);
  (void)seed48(seedv);
  (void)initstate_r(321, state, sizeof(state), &rd);
  (void)srandom_r(654, &rd);
  (void)srand48_r(987, &d48);

  int a = rand();
  long b = random();
  double c = drand48();
  long d = lrand48();
  long e = mrand48();
  (void)random_r(&rd, &rr);
  int f = rand_r(&rand_r_seed);
  (void)drand48_r(&d48, &dr);
  (void)lrand48_r(&d48, &lr);
  (void)mrand48_r(&d48, &mr);

  qdmsan_sink_l = (long)a ^ b ^ (long)(c * 1000000.0) ^ d ^ e ^ rr ^ f ^
                  (long)(dr * 1000000.0) ^ lr ^ mr;
  if (qdmsan_sink_l & 1) return 0;
  return 0;
}
