#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "dmsanfuzz.h"

static void set_plane(struct dmsan_fast_map *map, uint8_t plane,
                      uint64_t sum, uint64_t rotl, uint64_t count) {
  switch (plane) {
    case QDMSAN_PLANE_UUM:
      map->sum_signature = sum;
      map->rotl_signature = rotl;
      map->total_count = count;
      break;
    case QDMSAN_PLANE_OOB:
      map->padding[QDMSAN_FAST_OOB_SUM_IDX] = sum;
      map->padding[QDMSAN_FAST_OOB_ROTL_IDX] = rotl;
      map->padding[QDMSAN_FAST_OOB_COUNT_IDX] = count;
      break;
    case QDMSAN_PLANE_UAF:
      map->padding[QDMSAN_FAST_UAF_SUM_IDX] = sum;
      map->padding[QDMSAN_FAST_UAF_ROTL_IDX] = rotl;
      map->padding[QDMSAN_FAST_UAF_COUNT_IDX] = count;
      break;
    default:
      assert(0 && "unknown plane");
  }
}

int main(void) {
  _Static_assert(sizeof(struct dmsan_fast_map) == 128,
                 "fast-map ABI must remain 128 bytes");
  _Static_assert(offsetof(struct dmsan_fast_map, padding) == 72,
                 "reserved plane lanes moved");

  struct dmsan_fast_map r1 = {0}, r2 = {0}, r3 = {0};
  set_plane(&r1, QDMSAN_PLANE_UUM, 1, 2, 1);
  set_plane(&r2, QDMSAN_PLANE_UUM, 1, 2, 1);
  set_plane(&r3, QDMSAN_PLANE_UUM, 1, 2, 1);
  struct qdmsan_plane_verdict v = qdmsan_classify_triplet(&r1, &r2, &r3);
  assert(v.candidate_mask == 0 && v.confirmed_mask == 0 && v.nondet_mask == 0);

  set_plane(&r2, QDMSAN_PLANE_OOB, 20, 21, 1);
  set_plane(&r1, QDMSAN_PLANE_OOB, 10, 11, 1);
  set_plane(&r3, QDMSAN_PLANE_OOB, 10, 11, 1);
  v = qdmsan_classify_triplet(&r1, &r2, &r3);
  assert(v.candidate_mask == QDMSAN_PLANE_OOB);
  assert(v.confirmed_mask == QDMSAN_PLANE_OOB);
  assert(v.nondet_mask == 0);
  assert(qdmsan_report_triplet_complete(&r1, &r2, &r3));

  set_plane(&r1, QDMSAN_PLANE_UAF, 30, 31, 1);
  set_plane(&r2, QDMSAN_PLANE_UAF, 40, 41, 1);
  set_plane(&r3, QDMSAN_PLANE_UAF, 50, 51, 1);
  v = qdmsan_classify_triplet(&r1, &r2, &r3);
  assert(v.candidate_mask == (QDMSAN_PLANE_OOB | QDMSAN_PLANE_UAF));
  assert(v.confirmed_mask == QDMSAN_PLANE_OOB);
  assert(v.nondet_mask == QDMSAN_PLANE_UAF);

  set_plane(&r1, QDMSAN_PLANE_UUM, 60, 61, 1);
  set_plane(&r2, QDMSAN_PLANE_UUM, 70, 71, 1);
  set_plane(&r3, QDMSAN_PLANE_UUM, 60, 61, 1);
  set_plane(&r3, QDMSAN_PLANE_UAF, 30, 31, 1);
  v = qdmsan_classify_triplet(&r1, &r2, &r3);
  assert(v.candidate_mask == QDMSAN_PLANE_ALL);
  assert(v.confirmed_mask == QDMSAN_PLANE_ALL);
  assert(v.nondet_mask == 0);
  return 0;
}
