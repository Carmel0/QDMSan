/*
   american fuzzy lop++ - DMSAN differential fuzzing header
   --------------------------------------------------------

   DMSAN (Differential Memory Sanitizer) integration for AFL++.

   This implements differential testing to detect uninitialized memory usage
   without the overhead of shadow memory tracking.

   Detection strategy (unified with dmsanfork-diff):
     - Run 1: poison=0x11, baseline
     - Run 2: poison=0x22, detect uninit memory  (Run1 vs Run2)
     - Run 3: poison=0x11, non-determinism check (Run1 vs Run3)

   Copyright 2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _AFL_DMSANFUZZ_H
#define _AFL_DMSANFUZZ_H

#include "config.h"
#include "types.h"
#include <stdint.h>

/* ========== DMSAN Fast Mode Shared Memory Structure ========== */

/* This must match the structure in DMSAN runtime library */
struct dmsan_fast_map {

  /* First cache line (64 bytes) */
  uint64_t sum_signature;       /* offset 0: ABI field name; current S1 lane1 digest sink */
  uint64_t rotl_signature;      /* offset 8: ABI field name; current S1 lane2 digest sink */
  uint64_t multiply_signature;  /* offset 16: ABI-reserved third lane (currently unused in mainline fast mode) */
  uint64_t total_count;         /* offset 24 */

  /* Fixed values for deterministic testing */
  uint64_t fixed_time_sec;      /* offset 32: base time (seconds) */
  uint64_t fixed_time_usec;     /* offset 40: base time (microseconds) */
  uint64_t fixed_rand_base;     /* offset 48: base random value */
  uint64_t fixed_tsc_base;      /* offset 56: base value for rdtsc */

  /* Second cache line (64 bytes) */
  uint64_t fixed_rdrand_base;   /* offset 64: base value for rdrand */
  /* QDMSan keeps its OOB/UAF differential lanes in the ABI-reserved tail.
     LLVM DMSan leaves these words zero and continues to use only the first
     semantic lane above. */
  uint64_t padding[7];          /* offset 72-120 */

} __attribute__((aligned(64)));

/* QDMSan fast-map ABI. The map remains exactly 128 bytes. */
#define QDMSAN_FAST_OOB_SUM_IDX 0U
#define QDMSAN_FAST_OOB_ROTL_IDX 1U
#define QDMSAN_FAST_OOB_COUNT_IDX 2U
#define QDMSAN_FAST_UAF_SUM_IDX 3U
#define QDMSAN_FAST_UAF_ROTL_IDX 4U
#define QDMSAN_FAST_UAF_COUNT_IDX 5U
#define QDMSAN_FAST_ABI_IDX 6U
#define QDMSAN_FAST_ABI_VERSION 1ULL

#define QDMSAN_PLANE_UUM 0x01U
#define QDMSAN_PLANE_OOB 0x02U
#define QDMSAN_PLANE_UAF 0x04U
#define QDMSAN_PLANE_ALL \
  (QDMSAN_PLANE_UUM | QDMSAN_PLANE_OOB | QDMSAN_PLANE_UAF)

struct qdmsan_plane_verdict {

  uint8_t candidate_mask; /* Run1 differs from Run2 */
  uint8_t confirmed_mask; /* candidate and Run1 equals Run3 */
  uint8_t nondet_mask;    /* candidate and Run1 differs from Run3 */

};

static inline uint64_t qdmsan_plane_sum(const struct dmsan_fast_map *sig,
                                        uint8_t plane) {

  if (!sig) { return 0; }
  switch (plane) {
    case QDMSAN_PLANE_UUM:
      return sig->sum_signature;
    case QDMSAN_PLANE_OOB:
      return sig->padding[QDMSAN_FAST_OOB_SUM_IDX];
    case QDMSAN_PLANE_UAF:
      return sig->padding[QDMSAN_FAST_UAF_SUM_IDX];
    default:
      return 0;
  }

}

static inline uint64_t qdmsan_plane_rotl(const struct dmsan_fast_map *sig,
                                         uint8_t plane) {

  if (!sig) { return 0; }
  switch (plane) {
    case QDMSAN_PLANE_UUM:
      return sig->rotl_signature;
    case QDMSAN_PLANE_OOB:
      return sig->padding[QDMSAN_FAST_OOB_ROTL_IDX];
    case QDMSAN_PLANE_UAF:
      return sig->padding[QDMSAN_FAST_UAF_ROTL_IDX];
    default:
      return 0;
  }

}

static inline uint64_t qdmsan_plane_count(const struct dmsan_fast_map *sig,
                                          uint8_t plane) {

  if (!sig) { return 0; }
  switch (plane) {
    case QDMSAN_PLANE_UUM:
      return sig->total_count;
    case QDMSAN_PLANE_OOB:
      return sig->padding[QDMSAN_FAST_OOB_COUNT_IDX];
    case QDMSAN_PLANE_UAF:
      return sig->padding[QDMSAN_FAST_UAF_COUNT_IDX];
    default:
      return 0;
  }

}

static inline uint8_t qdmsan_plane_signatures_equal(
    const struct dmsan_fast_map *a, const struct dmsan_fast_map *b,
    uint8_t plane) {

  return a && b && qdmsan_plane_sum(a, plane) == qdmsan_plane_sum(b, plane) &&
         qdmsan_plane_rotl(a, plane) == qdmsan_plane_rotl(b, plane) &&
         qdmsan_plane_count(a, plane) == qdmsan_plane_count(b, plane);

}

static inline uint8_t qdmsan_fast_signatures_equal(
    const struct dmsan_fast_map *a, const struct dmsan_fast_map *b) {

  return qdmsan_plane_signatures_equal(a, b, QDMSAN_PLANE_UUM) &&
         qdmsan_plane_signatures_equal(a, b, QDMSAN_PLANE_OOB) &&
         qdmsan_plane_signatures_equal(a, b, QDMSAN_PLANE_UAF);

}

static inline uint8_t qdmsan_fast_map_has_checkpoints(
    const struct dmsan_fast_map *sig) {

  return sig &&
         (qdmsan_plane_count(sig, QDMSAN_PLANE_UUM) ||
          qdmsan_plane_count(sig, QDMSAN_PLANE_OOB) ||
          qdmsan_plane_count(sig, QDMSAN_PLANE_UAF));

}

static inline uint8_t qdmsan_report_triplet_complete(
    const struct dmsan_fast_map *run1, const struct dmsan_fast_map *run2,
    const struct dmsan_fast_map *run3) {

  return qdmsan_fast_map_has_checkpoints(run1) &&
         qdmsan_fast_map_has_checkpoints(run2) &&
         qdmsan_fast_map_has_checkpoints(run3);

}

static inline struct qdmsan_plane_verdict qdmsan_classify_triplet(
    const struct dmsan_fast_map *run1, const struct dmsan_fast_map *run2,
    const struct dmsan_fast_map *run3) {

  struct qdmsan_plane_verdict verdict = {0, 0, 0};
  static const uint8_t planes[] = {QDMSAN_PLANE_UUM, QDMSAN_PLANE_OOB,
                                    QDMSAN_PLANE_UAF};

  for (unsigned i = 0; i < sizeof(planes) / sizeof(planes[0]); ++i) {
    uint8_t plane = planes[i];
    if (qdmsan_plane_signatures_equal(run1, run2, plane)) { continue; }
    verdict.candidate_mask |= plane;
    if (qdmsan_plane_signatures_equal(run1, run3, plane)) {
      verdict.confirmed_mask |= plane;
    } else {
      verdict.nondet_mask |= plane;
    }
  }

  return verdict;

}

/* Environment variable names for DMSAN shared memory */
#define DMSAN_FAST_SHM_ENV_VAR "__DMSAN_FAST_SHM_ID"
#define DMSAN_FEEDBACK_SHM_ENV_VAR "__DMSAN_FEEDBACK_SHM_ID"
#define DMSAN_POISON_SHM_ENV_VAR "__DMSPVAL_SHM_ID"
#define DMSAN_SITEMAP_SHM_ENV_VAR "__DMSAN_SITEMAP_SHM_ID"
#define DMSAN_FULL_SHM_ENV_VAR "__DMSAN_FULL_SHM_ID"

#define DMSAN_FEEDBACK_MAP_BITS 16
#define DMSAN_FEEDBACK_MAP_SIZE (1u << DMSAN_FEEDBACK_MAP_BITS)
#define DMSAN_SITE_CLASS_BITS 16
#define DMSAN_SITE_CLASS_ENTRIES (1u << DMSAN_SITE_CLASS_BITS)
#define DMSAN_SITE_CLASS_BUCKETS 16u
#define DMSAN_FEEDBACK_MAGIC 0x4644424bU
#define DMSAN_FEEDBACK_VERSION 2U

struct dmsan_feedback_header {
  uint32_t magic;
  uint32_t version;
  uint32_t map_size;
  uint32_t site_map_entries;
} __attribute__((packed, aligned(16)));

struct dmsan_feedback_shm {
  struct dmsan_feedback_header header;
  uint8_t map[DMSAN_FEEDBACK_MAP_SIZE];
  uint16_t site_map[DMSAN_SITE_CLASS_ENTRIES];
} __attribute__((aligned(64)));

#define DMSAN_FULL_DEFAULT_SIZE (1u << 20)
#define DMSAN_FULL_MAX_SIZE (1u << 24)
#define DMSAN_FULL_MIN_SIZE (1u << 16)
#define DMSAN_FULL_MAGIC 0x46554c4cU
#define DMSAN_FULL_MODE_HASH 1U
#define DMSAN_FULL_ABI_VERSION 2U
#define DMSAN_FULL_ENTRY_FLAG_COLLISION 1U

struct dmsan_full_entry {
  uint64_t value;
  uint64_t pc;
  uint32_t site_id;
  uint32_t flags;
  uint64_t reserved;
} __attribute__((packed, aligned(16)));

struct dmsan_full_meta {
  uint64_t magic;
  uint64_t array_size;
  uint64_t write_index;
  uint64_t total_count;
  uint64_t overflow_count;
  uint64_t module_base;
  uint64_t mode;
  uint64_t abi_version;
} __attribute__((aligned(64)));

struct dmsan_full_shm {
  struct dmsan_full_meta meta;
  struct dmsan_full_entry entries[];
};

static inline u8 dmsan_fast_map_has_checkpoints(
    const struct dmsan_fast_map *sig) {

  return sig && sig->total_count != 0;

}

static inline u8 dmsan_report_triplet_complete(
    const struct dmsan_fast_map *run1, const struct dmsan_fast_map *run2,
    const struct dmsan_fast_map *run3) {

  return dmsan_fast_map_has_checkpoints(run1) &&
         dmsan_fast_map_has_checkpoints(run2) &&
         dmsan_fast_map_has_checkpoints(run3);

}

/* ========== DMSAN Sitemap (Full mode file:line reporting) ========== */

#define DMSAN_SITEMAP_MAX_ENTRIES 65536
#define DMSAN_SITEMAP_FILENAME_LEN 52

struct dmsan_sitemap_entry {
  uint32_t site_id;
  uint32_t line;
  uint32_t col;
  char filename[DMSAN_SITEMAP_FILENAME_LEN];
} __attribute__((packed));

static inline const struct dmsan_sitemap_entry *dmsan_sitemap_lookup(
    const struct dmsan_sitemap_entry *entries, uint32_t count,
    uint32_t site_id) {

  if (!entries || !site_id) { return NULL; }

  for (uint32_t i = 0; i < count; ++i) {
    if (entries[i].site_id == site_id) { return &entries[i]; }
  }

  return NULL;

}

/* Default poison values for the three runs (unified with dmsanfork-diff) */
#define DMSAN_POISON_RUN1 0x11  /* Baseline */
#define DMSAN_POISON_RUN2 0x22  /* Different poison: detects uninit memory */
#define DMSAN_POISON_RUN3 0x11  /* Same as Run1: verify determinism (Run1 vs Run3) */

/* ========== DMSAN Detection Results ========== */

typedef enum {

  DMSAN_CLEAN = 0,             /* No issue detected */
  DMSAN_BUG_FOUND = 1,         /* Uninitialized memory usage detected */
  DMSAN_NON_DETERMINISTIC = 2, /* Program behavior is non-deterministic */
  DMSAN_CRASH = 3,             /* Program crashed during execution */
  DMSAN_DEDUPED = 4,           /* Run3 skipped: trace already in virgin_dmsan */
  DMSAN_TIMEOUT = 5,           /* DMSAN sidecar/confirmation execution timed out */

} dmsan_result_t;

/* ========== DMSAN Finding Record ========== */

typedef struct dmsan_finding {

  u64            id;           /* Finding ID */
  dmsan_result_t result;       /* Result type */
  u64            timestamp;    /* Unix timestamp */

  /* Signatures from three runs */
  u64 sig1_sum, sig1_rotl, sig1_mul, sig1_count;
  u64 sig2_sum, sig2_rotl, sig2_mul, sig2_count;
  u64 sig3_sum, sig3_rotl, sig3_mul, sig3_count;

  /* QDMSan plane classification. Zero for compiler-based DMSan findings. */
  u8 candidate_mask;
  u8 confirmed_mask;
  u8 nondet_mask;

  /* Crash info (if result == DMSAN_CRASH) */
  s32 crash_run;               /* Which run crashed (1, 2, or 3) */
  s32 crash_signal;            /* Crash signal number */

  /* Source tracking */
  u8 *source_file;             /* Original queue entry that led to this */

} dmsan_finding_t;

/* DMSAN runtime model.
 *
 * Two compile-time dimensions decided by afl-cc:
 *   AFL_DMSAN_MODE  = fast | fast+aux | full
 *   AFL_DMSAN_DEPLOY= sidecar | inline
 *
 * Three runtime aux roles (only meaningful when the binary was built with
 * MODE=fast+aux). Each is independent; selecting one does not implicitly
 * enable another.
 *
 *   AFL_DMSAN_AUX_FEEDBACK : aux per-site novelty drives queue scoring
 *                            (sanitizer guidance)
 *   AFL_DMSAN_AUX_CACHE    : Run1's site_map hash skips Run2 on hit
 *                            (execution reuse)
 *   AFL_DMSAN_AUX_NONDET   : when signature reports NONDET, aux per-site
 *                            disambiguates and may rescue to BUG
 *                            (non-determinism isolation)
 *
 * The runtime keeps only the role bits, the "is aux compiled in" probe result,
 * and the site_map-based aux cache key.
 */

#define DMSAN_CLEAN_CACHE_DEFAULT_ENTRIES 256U

struct dmsan_clean_cache_entry {

  u64 hash;
  u32 len;
  u8 *buf;

};

#define DMSAN_AUX_CACHE_SIZE 131072U

struct dmsan_aux_cache_entry {

  u64 key;
  u8  result;

};

/* ========== DMSAN API Functions ========== */

struct afl_state;
struct afl_forkserver;

/* Initialize DMSAN subsystem */
void dmsan_init(struct afl_state *afl);

/* Initialize integrated-inline DMSAN mode (main exec = Run1) */
void dmsan_integrated_init(struct afl_state *afl);

/* Setup DMSAN shared memory */
void dmsan_setup_shm(struct afl_state *afl);

/* Perform three-run differential check */
dmsan_result_t dmsan_check(struct afl_state *afl, u8 *buf, u32 len);

/* Perform integrated-inline differential check after main exec completed Run1 */
dmsan_result_t dmsan_integrated_check(struct afl_state *afl, u8 *buf, u32 len);

/* Calibration reuse path: consume Run1 / Run2 signatures captured
   inside calibrate_case, only fall back to a fresh Run3 if they diverge.
   Returns DMSAN_CLEAN | _NON_DETERMINISTIC | _BUG_FOUND | _CRASH. Caller must
   have set afl->dmsan_cal_have_sigs and populated dmsan_cal_sig1/sig2. */
dmsan_result_t dmsan_check_from_calibration(struct afl_state *afl, u8 *buf,
                                            u32 len);

/* Perform differential check solely for MSan cross-classification.
   Identical to dmsan_check() but tallied in dmsan_crosscheck_checks rather
   than dmsan_direct_checks, keeping sidecar stats uncontaminated. */
dmsan_result_t dmsan_crosscheck(struct afl_state *afl, u8 *buf, u32 len);

/* Clear feedback/siteclass SHM maps (not fast_map).  Called after each
   integrated check so the next Run1 starts with clean maps. */
void dmsan_clear_feedback_maps(struct afl_state *afl);

/* Opportunistic old-path probe:
   - schedule a single Run1 on logarithmically sampled old traces
   - only escalate to full differential checking if Run1 reports new feedback */
dmsan_result_t dmsan_maybe_probe_feedback(struct afl_state *afl, u8 *buf,
                                          u32 len, u64 trace_cksum,
                                          u8 *executed);

/* Run a single fixed-poison DMSAN execution and snapshot the fast map.
   Returns FSRV_RUN_* as u8. */
u8 dmsan_sample_run(struct afl_state *afl, u8 *buf, u32 len, u8 poison,
                    struct dmsan_fast_map *snapshot,
                    uint16_t *siteclass_snapshot);

/* Save finding to dmsan_findings directory */
u8 dmsan_save_finding(struct afl_state *afl, u8 *buf, u32 len,
                      dmsan_result_t result, dmsan_finding_t *finding);

/* Save categorized combined-MSAN/DMSAN case into msan_only/ or dmsan_only/. */
u8 dmsan_save_categorized_finding(struct afl_state *afl, u8 *buf, u32 len,
                                  const char *subdir, u64 *next_id,
                                  u64 *saved_count);

/* Update the JSON report */
void dmsan_update_report(struct afl_state *afl);

/* Diagnostic replay: AFL_DMSAN_REPLAY_FILE runs dmsan_check() on a single file
   and dumps "<path>.sig" alongside it before exiting. Normal fuzzing writes
   finding .sig sidecars only when DMSAN debug artifacts are enabled with
   AFL_DMSAN_DEBUG=1 or AFL_DMSAN_DUMP_SIG=1. */
void dmsan_replay_single_file(struct afl_state *afl, const char *path);

/* Restore persisted finding dedup state on resume. */
void dmsan_load_dedup_state(struct afl_state *afl);

/* Scratch buffer for simplified coverage traces */
u8 *dmsan_ensure_trace_scratch(struct afl_state *afl, u32 map_size);

/* Cleanup DMSAN resources */
void dmsan_deinit(struct afl_state *afl);

/* Exec child for DMSAN forkserver */
void dmsan_exec_child(struct afl_forkserver *fsrv, char **argv);

/* Read sitemap from SHM after forkserver start (full mode only). */
void dmsan_read_sitemap(struct afl_state *afl);

/* Get result name string */
static inline const char *dmsan_result_name(dmsan_result_t result) {

  switch (result) {

    case DMSAN_CLEAN:
      return "clean";
    case DMSAN_BUG_FOUND:
      return "bug";
    case DMSAN_NON_DETERMINISTIC:
      return "nondet";
    case DMSAN_CRASH:
      return "crash";
    case DMSAN_DEDUPED:
      return "deduped";
    case DMSAN_TIMEOUT:
      return "timeout";
    default:
      return "unknown";

  }

}

#endif /* _AFL_DMSANFUZZ_H */
