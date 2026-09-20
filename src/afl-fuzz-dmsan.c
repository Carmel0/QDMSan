/*
   american fuzzy lop++ - DMSAN differential fuzzing
   --------------------------------------------------

   DMSAN (Differential Memory Sanitizer) integration for AFL++.

   Differential testing strategy (unified with dmsanfork-diff):
     - Run 1: poison=0x11, delay=0 (baseline)
     - Run 2: poison=0x22, delay=0 (detect uninit memory)
     - Run 3: poison=0x11, delay=0 (non-determinism check)
     - Compare: Run1 vs Run3 -> non-determinism
                Run1 vs Run2 -> uninitialized memory detected

   Copyright 2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#include "afl-fuzz.h"
#include "dmsanfuzz.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ========== Helper Functions ========== */

static inline u8 dmsan_clean_cache_lookup(afl_state_t *afl, u8 *buf, u32 len,
                                          u64 input_hash);
static inline void dmsan_clean_cache_insert(afl_state_t *afl, u8 *buf, u32 len,
                                            u64 input_hash);
static inline void dmsan_read_config(afl_state_t *afl);
static inline void dmsan_alloc_aux_cache(afl_state_t *afl);
static inline void dmsan_ensure_trace_backup(afl_state_t *afl, u32 map_size);
static inline u64 dmsan_make_aux_cache_key(afl_state_t          *afl,
                                           const u16            *aux_snapshot);
static inline u8 dmsan_aux_cache_lookup_clean(afl_state_t *afl, u64 key);
static inline void dmsan_aux_cache_insert_clean(afl_state_t *afl, u64 key);
static inline void dmsan_save_aux_snapshot(afl_state_t *afl, u16 *target);
static inline u8 dmsan_aux_has_new_bits_for_map(afl_state_t *afl,
                                                const u16 *current);
static inline u8 dmsan_aux_has_new_bits(afl_state_t *afl);
static inline void dmsan_analyze_aux_nondet(afl_state_t *afl);
static dmsan_result_t dmsan_aux_compute_verdict(afl_state_t *afl);
static void dmsan_save_nondet_debug(afl_state_t *afl, u8 *buf, u32 len);
static void dmsan_write_sig_sidecar(afl_state_t *afl, const char *path,
                                    dmsan_result_t result,
                                    const struct dmsan_fast_map *s1,
                                    const struct dmsan_fast_map *s2,
                                    const struct dmsan_fast_map *s3);
static inline dmsan_result_t dmsan_timeout_result(afl_state_t *afl, u8 *buf,
                                                  u32 len, u8 run_id);
static void dmsan_recover_dir_state(afl_state_t *afl, const char *subdir,
                                    u64 *saved_count, u64 *next_id);
static void dmsan_recover_findings_state(afl_state_t *afl);
static void dmsan_save_dedup_state_one(afl_state_t *afl, const char *name,
                                       const u8 *map, size_t map_size);
static void dmsan_persist_dedup_state(afl_state_t *afl);

static inline u64 dmsan_rand_u64(void) {

  return ((u64)rand() << 32) | (u64)rand();

}

static inline int dmsan_ascii_lower(int c) {

  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;

}

static inline u8 dmsan_str_eq_ci(const char *s, const char *lit) {

  if (!s || !lit) { return 0; }
  while (*s && *lit) {
    if (dmsan_ascii_lower((unsigned char)*s) !=
        dmsan_ascii_lower((unsigned char)*lit)) {
      return 0;
    }
    ++s;
    ++lit;
  }
  return !*s && !*lit;

}

static inline const char *qdmsan_plane_mask_name(u8 mask) {

  switch (mask & QDMSAN_PLANE_ALL) {
    case 0:
      return "none";
    case QDMSAN_PLANE_UUM:
      return "UUM";
    case QDMSAN_PLANE_OOB:
      return "OOB";
    case QDMSAN_PLANE_UUM | QDMSAN_PLANE_OOB:
      return "UUM|OOB";
    case QDMSAN_PLANE_UAF:
      return "UAF";
    case QDMSAN_PLANE_UUM | QDMSAN_PLANE_UAF:
      return "UUM|UAF";
    case QDMSAN_PLANE_OOB | QDMSAN_PLANE_UAF:
      return "OOB|UAF";
    case QDMSAN_PLANE_ALL:
      return "UUM|OOB|UAF";
    default:
      return "invalid";
  }

}

static inline void dmsan_reset_current_finding(afl_state_t *afl) {

  afl->dmsan_current_finding.crash_run = 0;
  afl->dmsan_current_finding.crash_signal = 0;
  afl->dmsan_current_finding.candidate_mask = 0;
  afl->dmsan_current_finding.confirmed_mask = 0;
  afl->dmsan_current_finding.nondet_mask = 0;

}

static inline u8 dmsan_read_env_u64(const char *name, u64 *out) {

  const char *value = getenv(name);
  if (!value || !*value) { return 0; }

  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(value, &end, 0);
  if (errno || !end || *end) {

    WARNF("Ignoring invalid %s='%s'", name, value);
    return 0;

  }

  *out = (u64)parsed;
  return 1;

}

static inline u8 dmsan_read_replay_u64(const char *short_name, u64 *out) {

  char name[96];
  snprintf(name, sizeof(name), "AFL_DMSAN_REPLAY_%s", short_name);
  if (dmsan_read_env_u64(name, out)) { return 1; }

  snprintf(name, sizeof(name), "DMSAN_REPLAY_%s", short_name);
  return dmsan_read_env_u64(name, out);

}

/* Compare two fast map signatures */
static inline u8 dmsan_signatures_equal(const struct dmsan_fast_map *s1,
                                        const struct dmsan_fast_map *s2) {

  /* Note: multiply_signature is ABI-reserved and not updated by the runtime.
   * Comparing it would always return equal, so we skip it. */
  return (s1->sum_signature == s2->sum_signature &&
          s1->rotl_signature == s2->rotl_signature &&
          s1->total_count == s2->total_count);

}

/* Compiler-based DMSan owns only the semantic (UUM) lane. QDMSan compares
   all three independent differential lanes while preserving the same 2+1
   selector schedule. */
static inline u8 dmsan_active_signatures_equal(
    const afl_state_t *afl, const struct dmsan_fast_map *s1,
    const struct dmsan_fast_map *s2) {

  return afl->qdmsan_enabled ? qdmsan_fast_signatures_equal(s1, s2)
                             : dmsan_signatures_equal(s1, s2);

}

static inline u8 dmsan_active_triplet_complete(
    const afl_state_t *afl, const struct dmsan_fast_map *s1,
    const struct dmsan_fast_map *s2, const struct dmsan_fast_map *s3) {

  return afl->qdmsan_enabled ? qdmsan_report_triplet_complete(s1, s2, s3)
                             : dmsan_report_triplet_complete(s1, s2, s3);

}

/* Clear the shared memory map */
static inline void dmsan_clear_map(afl_state_t *afl) {

  if (afl->dmsan_shm_fast) {

    struct dmsan_fast_map *map = (struct dmsan_fast_map *)afl->dmsan_shm_fast;
    memset(map, 0, sizeof(struct dmsan_fast_map));

    /* DEBUG: Verify the clear worked */
    if (afl->debug) {
      DEBUGF("DMSAN clear_map: shm_fast=%p, sum=%llx, cnt=%llu\n",
             map,
             (unsigned long long)map->sum_signature,
             (unsigned long long)map->total_count);
    }

  }

  /* Only clear the aux site_map when the binary actually has aux compiled. */
  if (afl->dmsan_shm_feedback && afl->dmsan_aux_compiled) {

    struct dmsan_feedback_shm *feedback =
        (struct dmsan_feedback_shm *)afl->dmsan_shm_feedback;
    memset(feedback->site_map, 0, sizeof(feedback->site_map));

  }

  if (afl->dmsan_shm_full && afl->dmsan_full_mode) {

    struct dmsan_full_shm *full = (struct dmsan_full_shm *)afl->dmsan_shm_full;
    u64 array_size = full->meta.array_size;
    memset(full->entries, 0,
           (size_t)array_size * sizeof(struct dmsan_full_entry));
    full->meta.write_index = 0;
    full->meta.total_count = 0;
    full->meta.overflow_count = 0;

  }

}

/* Clear only the aux site_map (not fast_map).  Used in inline mode after each
   check to prepare a clean Run1 site_map for the next input.  site_map uses
   atomic_or accumulation -> stale data would converge to all-1s. */
void dmsan_clear_feedback_maps(afl_state_t *afl) {

  if (afl->dmsan_shm_feedback && afl->dmsan_aux_compiled) {

    struct dmsan_feedback_shm *feedback =
        (struct dmsan_feedback_shm *)afl->dmsan_shm_feedback;
    memset(feedback->site_map, 0, sizeof(feedback->site_map));

  }

}

/* Set poison value in shared memory */
static inline void dmsan_set_poison(afl_state_t *afl, u8 poison_value) {

  if (afl->dmsan_shm_poison) { *afl->dmsan_shm_poison = poison_value; }

}

/* Set fixed values for deterministic execution */
static inline void dmsan_set_fixed_values(afl_state_t *afl) {

  if (afl->dmsan_shm_fast) {

    struct dmsan_fast_map *map = (struct dmsan_fast_map *)afl->dmsan_shm_fast;
    map->fixed_time_sec = afl->dmsan_fixed_time_sec;
    map->fixed_time_usec = afl->dmsan_fixed_time_usec;
    map->fixed_rand_base = afl->dmsan_fixed_rand_base;
    map->fixed_tsc_base = afl->dmsan_fixed_tsc_base;
    map->fixed_rdrand_base = afl->dmsan_fixed_rdrand_base;

  }

}

/* Save snapshot from shared memory to local memory */
static inline void dmsan_save_snapshot(afl_state_t          *afl,
                                       struct dmsan_fast_map *target) {

  if (afl->dmsan_shm_fast && target) {

    memcpy(target, afl->dmsan_shm_fast, sizeof(struct dmsan_fast_map));

  }

}

static inline void dmsan_save_aux_snapshot(afl_state_t *afl, u16 *target) {

  if (!afl->dmsan_aux_compiled || !afl->dmsan_shm_feedback || !target) {
    return;
  }

  struct dmsan_feedback_shm *feedback =
      (struct dmsan_feedback_shm *)afl->dmsan_shm_feedback;
  memcpy(target, feedback->site_map, sizeof(feedback->site_map));

}

static inline void dmsan_scrub_snapshot(struct dmsan_fast_map *snapshot,
                                        u16 *aux_snapshot) {

  if (snapshot) { memset(snapshot, 0, sizeof(*snapshot)); }
  if (aux_snapshot) {
    memset(aux_snapshot, 0, sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }

}

static inline u8 dmsan_should_write_sig_sidecar(afl_state_t *afl) {

  const char *replay_path = getenv("AFL_DMSAN_REPLAY_FILE");
  return afl->dmsan_debug_dump_sig || (replay_path && *replay_path);

}

static inline u8 dmsan_should_apply_replay_overrides(void) {

  const char *replay_path = getenv("AFL_DMSAN_REPLAY_FILE");
  return replay_path && *replay_path;

}

/* Per-site map novelty scan. Returns 0 when nothing is new, and 2 when new
   bits were OR'd into the virgin map for queue scoring. */
static inline u8 dmsan_aux_has_new_bits_for_map(afl_state_t *afl,
                                                const u16 *current) {

  if (!afl->dmsan_aux_compiled || !current || !afl->virgin_dmsan_aux) {
    return 0;
  }

  u16 *virgin = (u16 *)afl->virgin_dmsan_aux;
  u8   ret = 0;

  for (u32 i = 0; i < DMSAN_SITE_CLASS_ENTRIES; ++i) {

    u16 new_bits = current[i] & virgin[i];
    if (new_bits) {

      ret = 2;
      virgin[i] &= (u16)~current[i];

    }

  }

  return ret;

}

static inline u8 dmsan_aux_has_new_bits(afl_state_t *afl) {

  if (!afl->dmsan_shm_feedback) { return 0; }

  struct dmsan_feedback_shm *feedback =
      (struct dmsan_feedback_shm *)afl->dmsan_shm_feedback;
  return dmsan_aux_has_new_bits_for_map(afl, feedback->site_map);

}

static dmsan_result_t dmsan_aux_compute_verdict_for_maps(const u16 *m1,
                                                         const u16 *m2,
                                                         const u16 *m3) {

  if (!m1 || !m2 || !m3) { return DMSAN_CLEAN; }

  u8   any_bug = 0;
  u8   any_nondet = 0;

  for (u32 i = 0; i < DMSAN_SITE_CLASS_ENTRIES; ++i) {

    u16 v1 = m1[i], v2 = m2[i], v3 = m3[i];
    if (!(v1 | v2 | v3)) { continue; }
    if (v1 == v3 && v1 != v2) {
      any_bug = 1;
      break;  /* one BUG site is enough - final verdict locked */
    }
    if (v1 != v3) { any_nondet = 1; }

  }

  if (any_bug) { return DMSAN_BUG_FOUND; }
  if (any_nondet) { return DMSAN_NON_DETERMINISTIC; }
  return DMSAN_CLEAN;

}

/* Aux site_map verdict over the three runs, applied per site. A single per-site
   BUG dominates; otherwise any per-site NONDET dominates CLEAN. */
static dmsan_result_t dmsan_aux_compute_verdict(afl_state_t *afl) {

  if (!afl->dmsan_aux_compiled) { return DMSAN_CLEAN; }
  return dmsan_aux_compute_verdict_for_maps(afl->dmsan_aux_snapshot1,
                                            afl->dmsan_aux_snapshot2,
                                            afl->dmsan_aux_snapshot3);

}

static inline u8 dmsan_should_use_clean_cache(const afl_state_t *afl) {

  return afl->dmsan_clean_cache_enabled && afl->dmsan_clean_cache;

}

/* Map "0|off|on|1" -> 0/1; everything else -> FATAL. */
static inline u8 dmsan_parse_bool_env(const char *name, const char *val) {

  if (!val) { return 0; }
  if (!strcmp(val, "0") || dmsan_str_eq_ci(val, "off") ||
      dmsan_str_eq_ci(val, "false")) {
    return 0;
  }
  if (!strcmp(val, "1") || dmsan_str_eq_ci(val, "on") ||
      dmsan_str_eq_ci(val, "true")) {
    return 1;
  }
  FATAL("Unknown %s value '%s' (expected 0|1|off|on)", name, val);

}

static inline u32 dmsan_parse_uint_env(const char *name, const char *val) {

  if (!val || !*val || *val == '-') {
    FATAL("%s: expected a non-negative integer (0-1024), got '%s'", name,
          val ? val : "(null)");
  }
  errno = 0;
  char         *end;
  unsigned long v = strtoul(val, &end, 10);
  if (errno || *end || v > 1024) {
    FATAL("%s: expected a non-negative integer (0-1024), got '%s'", name, val);
  }
  return (u32)v;

}

static inline void dmsan_read_config(afl_state_t *afl) {

  static const struct {
    const char *name;
    const char *replacement;
  } kRetiredDmsanEnv[] = {
      {"AFL_USE_DMSAN", "AFL_DMSAN_MODE=fast"},
      {"AFL_USE_DMSAN_INLINE",
       "AFL_DMSAN_MODE=fast AFL_DMSAN_DEPLOY=inline"},
      {"AFL_USE_DMSAN_FULL", "AFL_DMSAN_MODE=full"},
      {"AFL_DMSAN_EXEC", "AFL_DMSAN_DEPLOY={sidecar|inline}"},
      {"AFL_DMSAN_FEEDBACK",
       "AFL_DMSAN_MODE=fast+aux + AFL_DMSAN_AUX_FEEDBACK=1"},
      {"AFL_DMSAN_L2", "AFL_DMSAN_MODE=fast+aux + AFL_DMSAN_AUX_CACHE=1"},
      {"AFL_DMSAN_SITECLASS", "AFL_DMSAN_MODE=fast+aux"},
  };
  for (size_t i = 0;
       i < sizeof(kRetiredDmsanEnv) / sizeof(kRetiredDmsanEnv[0]); ++i) {
    if (getenv(kRetiredDmsanEnv[i].name)) {
      FATAL("%s is no longer accepted; use %s (see docs/dmsan.md)",
            kRetiredDmsanEnv[i].name, kRetiredDmsanEnv[i].replacement);
    }
  }

  const char *qdmsan_mode = getenv("AFL_QDMSAN_MODE");
  const char *dmsan_mode = getenv("AFL_DMSAN_MODE");
  const char *deploy = qdmsan_mode ? getenv("AFL_QDMSAN_DEPLOY")
                                   : getenv("AFL_DMSAN_DEPLOY");
  const char *aux_fb_env = getenv("AFL_DMSAN_AUX_FEEDBACK");
  const char *aux_cache_env = getenv("AFL_DMSAN_AUX_CACHE");
  const char *aux_nondet_env = getenv("AFL_DMSAN_AUX_NONDET");
  const char *cal_reuse_env = getenv("AFL_DMSAN_CAL_REUSE");
  const char *run3_dedup_env = getenv("AFL_DMSAN_RUN3_DEDUP");
  const char *confirm_runs_env = getenv("AFL_DMSAN_CONFIRM_RUNS");
  const char *clean_cache = getenv("AFL_DMSAN_CLEAN_CACHE");
  const char *debug_env = getenv("AFL_DMSAN_DEBUG");
  const char *dump_sig_env = getenv("AFL_DMSAN_DUMP_SIG");
  const char *save_nondet_env = getenv("AFL_DMSAN_SAVE_NONDET");

  afl->qdmsan_enabled = qdmsan_mode && *qdmsan_mode;
  afl->dmsan_inline_mode = afl->qdmsan_enabled ? 1 : 0;
  afl->dmsan_full_mode = 0;
  afl->dmsan_aux_compiled = 0;
  afl->dmsan_clean_cache_enabled = 0;
  afl->dmsan_debug_enabled = 0;
  afl->dmsan_debug_dump_sig = 0;
  afl->dmsan_save_nondet = 0;
  afl->dmsan_aux_feedback = 0;
  afl->dmsan_aux_cache = 0;
  afl->dmsan_aux_nondet = 0;
  afl->dmsan_cal_reuse_enabled = 1;
  afl->dmsan_run3_dedup = 1;         /* default-on: AFL_DMSAN_RUN3_DEDUP=0 to disable */
  afl->dmsan_confirm_runs = 1;       /* default 1: AFL_DMSAN_CONFIRM_RUNS=0 to disable */
  if (afl->qdmsan_enabled && dmsan_mode && *dmsan_mode) {
    FATAL("AFL_QDMSAN_MODE cannot be combined with AFL_DMSAN_MODE");
  }

  const char *mode = afl->qdmsan_enabled ? qdmsan_mode : dmsan_mode;
  if (mode && *mode) {
    if (dmsan_str_eq_ci(mode, "fast")) {
      afl->dmsan_aux_compiled = 0;
      afl->dmsan_full_mode = 0;
    } else if (dmsan_str_eq_ci(mode, "fast+aux")) {
      afl->dmsan_aux_compiled = 1;
      afl->dmsan_full_mode = 0;
    } else if (dmsan_str_eq_ci(mode, "full")) {
      afl->dmsan_aux_compiled = 0;
      afl->dmsan_full_mode = 1;
    } else {
      FATAL("Unknown %s value '%s' (expected fast|fast+aux|full)",
            afl->qdmsan_enabled ? "AFL_QDMSAN_MODE" : "AFL_DMSAN_MODE",
            mode);
    }
  }

  /* aux_compiled is initially set from the role bits (any role on -> assume
     fast+aux binary). dmsan_init() will probe-and-correct after the first
     execution if the assumption is wrong. */

  if (deploy) {
    if (dmsan_str_eq_ci(deploy, "sidecar")) {
      afl->dmsan_inline_mode = 0;
    } else if (dmsan_str_eq_ci(deploy, "inline")) {
      afl->dmsan_inline_mode = 1;
    } else {
      FATAL("Unknown %s value '%s' (expected sidecar|inline)",
            afl->qdmsan_enabled ? "AFL_QDMSAN_DEPLOY" : "AFL_DMSAN_DEPLOY",
            deploy);
    }
  }

  afl->dmsan_aux_feedback =
      dmsan_parse_bool_env("AFL_DMSAN_AUX_FEEDBACK", aux_fb_env);
  afl->dmsan_aux_cache =
      dmsan_parse_bool_env("AFL_DMSAN_AUX_CACHE", aux_cache_env);
  afl->dmsan_aux_nondet =
      dmsan_parse_bool_env("AFL_DMSAN_AUX_NONDET", aux_nondet_env);
  if (cal_reuse_env) {
    afl->dmsan_cal_reuse_enabled =
        dmsan_parse_bool_env("AFL_DMSAN_CAL_REUSE", cal_reuse_env);
  }
  if (run3_dedup_env) {
    afl->dmsan_run3_dedup =
        dmsan_parse_bool_env("AFL_DMSAN_RUN3_DEDUP", run3_dedup_env);
  }
  if (confirm_runs_env) {
    afl->dmsan_confirm_runs =
        dmsan_parse_uint_env("AFL_DMSAN_CONFIRM_RUNS", confirm_runs_env);
  }
  if (debug_env) {
    afl->dmsan_debug_enabled =
        dmsan_parse_bool_env("AFL_DMSAN_DEBUG", debug_env);
  }
  afl->dmsan_debug_dump_sig = afl->dmsan_debug_enabled;
  afl->dmsan_save_nondet = afl->dmsan_debug_enabled;
  if (dump_sig_env) {
    afl->dmsan_debug_dump_sig =
        dmsan_parse_bool_env("AFL_DMSAN_DUMP_SIG", dump_sig_env);
  }
  if (save_nondet_env) {
    afl->dmsan_save_nondet =
        dmsan_parse_bool_env("AFL_DMSAN_SAVE_NONDET", save_nondet_env);
  }

  if (!afl->dmsan_aux_compiled) {
    afl->dmsan_aux_compiled =
        afl->dmsan_aux_feedback || afl->dmsan_aux_cache ||
        afl->dmsan_aux_nondet;
  }

  if (clean_cache) {
    if (!strcmp(clean_cache, "0") || dmsan_str_eq_ci(clean_cache, "off")) {
      afl->dmsan_clean_cache_enabled = 0;
    } else if (!strcmp(clean_cache, "1") ||
               dmsan_str_eq_ci(clean_cache, "on")) {
      afl->dmsan_clean_cache_enabled = 1;
    } else {
      FATAL("Unknown AFL_DMSAN_CLEAN_CACHE value '%s' (expected 0|1|off|on)",
            clean_cache);
    }
  }

  /* QDMSan's online oracle is deliberately an exact 2+1 protocol: two
     different-selector runs and exactly one same-selector confirmation when
     any UUM/OOB/UAF lane differs. Semantic-only caches, Run3 coverage dedup,
     and post-triplet confirmation runs would weaken that contract. */
  if (afl->qdmsan_enabled) {
    afl->dmsan_clean_cache_enabled = 0;
    afl->dmsan_aux_cache = 0;
    afl->dmsan_run3_dedup = 0;
    afl->dmsan_confirm_runs = 0;
  }

}

static inline void dmsan_alloc_aux_cache(afl_state_t *afl) {

  if (!afl->dmsan_aux_cache || afl->dmsan_aux_cache_table) { return; }

  afl->dmsan_aux_cache_table =
      ck_alloc(DMSAN_AUX_CACHE_SIZE * sizeof(struct dmsan_aux_cache_entry));

}

static inline void dmsan_ensure_trace_backup(afl_state_t *afl, u32 map_size) {

  if (afl->dmsan_trace_backup && afl->dmsan_trace_backup_size >= map_size) {
    return;
  }

  if (afl->dmsan_trace_backup) {

    ck_free(afl->dmsan_trace_backup);
    afl->dmsan_trace_backup = NULL;

  }

  afl->dmsan_trace_backup = ck_alloc(map_size + 8);
  afl->dmsan_trace_backup_size = map_size + 8;

}

u8 *dmsan_ensure_trace_scratch(afl_state_t *afl, u32 map_size) {

  u64 need = (u64)map_size + 8;

  if (afl->dmsan_trace_scratch &&
      afl->dmsan_trace_scratch_size >= need) {
    return afl->dmsan_trace_scratch;
  }

  if (afl->dmsan_trace_scratch) {

    ck_free(afl->dmsan_trace_scratch);
    afl->dmsan_trace_scratch = NULL;

  }

  afl->dmsan_trace_scratch = ck_alloc(need);
  afl->dmsan_trace_scratch_size = need;
  return afl->dmsan_trace_scratch;

}

/* Cache key: hash64 over the Run1 site_map snapshot. */
static inline u64 dmsan_make_aux_cache_key(afl_state_t *afl,
                                           const u16   *aux_snapshot) {

  if (!aux_snapshot) { return 0; }
  u64 key = hash64((u8 *)aux_snapshot,
                   sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES, HASH_CONST);
  (void)afl;
  return key ? key : 1;

}

/* Aux cache note: a hit skips Run2 + Run3, so cache hits suppress findings
   whenever two distinct executions hash to the same per-site bucket pattern. */
static inline u8 dmsan_aux_cache_lookup_clean(afl_state_t *afl, u64 key) {

  if (!afl->dmsan_aux_cache_table || !key) { return 0; }
  u32 slot = (u32)(key & (DMSAN_AUX_CACHE_SIZE - 1));

  for (u32 probe = 0; probe < 8; ++probe) {

    u32 idx = (slot + probe) & (DMSAN_AUX_CACHE_SIZE - 1);
    struct dmsan_aux_cache_entry *entry = &afl->dmsan_aux_cache_table[idx];

    if (!entry->key) { break; }
    if (entry->key == key) {

      if (entry->result == DMSAN_CLEAN) {

        ++afl->dmsan_aux_cache_hits;
        return 1;

      }

      break;

    }

  }

  ++afl->dmsan_aux_cache_misses;
  return 0;

}

static inline void dmsan_aux_cache_insert_clean(afl_state_t *afl, u64 key) {

  if (!afl->dmsan_aux_cache_table || !key) { return; }
  u32 slot = (u32)(key & (DMSAN_AUX_CACHE_SIZE - 1));

  for (u32 probe = 0; probe < 8; ++probe) {

    u32 idx = (slot + probe) & (DMSAN_AUX_CACHE_SIZE - 1);
    struct dmsan_aux_cache_entry *entry = &afl->dmsan_aux_cache_table[idx];

    if (!entry->key || entry->key == key) {

      entry->key = key;
      entry->result = DMSAN_CLEAN;
      ++afl->dmsan_aux_cache_inserts;
      return;

    }

  }

}

static inline u64 dmsan_clean_cache_hash(u8 *buf, u32 len) {

  return hash64(buf, len, HASH_CONST);

}

/* Per-site stable/unstable counts for nondeterminism diagnostics. */
static inline void dmsan_analyze_aux_nondet(afl_state_t *afl) {

  afl->dmsan_last_aux_stable_sites = 0;
  afl->dmsan_last_aux_unstable_sites = 0;

  if (!afl->dmsan_aux_nondet || !afl->dmsan_aux_compiled ||
      !afl->dmsan_aux_snapshot1 || !afl->dmsan_aux_snapshot2 ||
      !afl->dmsan_aux_snapshot3) {
    return;
  }

  u32 stable = 0;
  u32 unstable = 0;

  for (u32 i = 0; i < DMSAN_SITE_CLASS_ENTRIES; ++i) {

    u16 m1 = afl->dmsan_aux_snapshot1[i];
    u16 m2 = afl->dmsan_aux_snapshot2[i];
    u16 m3 = afl->dmsan_aux_snapshot3[i];
    if (!(m1 | m2 | m3)) { continue; }

    if (m1 == m3 && m1 != m2) {

      ++stable;

    } else if (m1 != m3) {

      ++unstable;

    }

  }

  afl->dmsan_last_aux_stable_sites = stable;
  afl->dmsan_last_aux_unstable_sites = unstable;
  if (stable) { afl->dmsan_nondet_site_inputs++; }
  afl->dmsan_nondet_site_polluted += unstable;

}

static void dmsan_recover_dir_state(afl_state_t *afl, const char *subdir,
                                    u64 *saved_count, u64 *next_id) {

  u8 *dir_path = alloc_printf("%s/%s", afl->out_dir, subdir);
  DIR *dir = opendir((char *)dir_path);

  *saved_count = 0;
  *next_id = 0;

  if (!dir) {

    ck_free(dir_path);
    return;

  }

  struct dirent *entry;
  u64 max_id = 0;

  while ((entry = readdir(dir)) != NULL) {

    if (strncmp(entry->d_name, "id:", 3) != 0) { continue; }

    char *end = NULL;
    u64 id = strtoull(entry->d_name + 3, &end, 10);
    if (end == entry->d_name + 3) { continue; }

    ++(*saved_count);
    if (id >= max_id) { max_id = id + 1; }

  }

  *next_id = max_id;
  closedir(dir);
  ck_free(dir_path);

}

static void dmsan_recover_findings_state(afl_state_t *afl) {

  /* Scan directories to recover finding counters and next IDs.
     NOTE: virgin_dmsan / virgin_msan_only / virgin_dmsan_only are NOT rebuilt
     from directory contents here - they restart as all-0xFF (unseen).  This
     is intentional and consistent with how AFL++ handles virgin_crash on
     resume: the bitmaps are rebuilt naturally as fuzzing continues.
     Consequence: the first new finding after resume may be a near-duplicate
     of an existing one if it happens to share the same simplified trace.
     KEEP_UNIQUE_DMSAN limits accumulation. */
  dmsan_recover_dir_state(afl, "dmsan_findings", &afl->saved_dmsan_findings,
                          &afl->dmsan_next_finding_id);

  if (afl->san_binary_length) {

    dmsan_recover_dir_state(afl, "msan_only", &afl->saved_msan_only,
                            &afl->msan_only_next_id);
    dmsan_recover_dir_state(afl, "dmsan_only", &afl->saved_dmsan_only,
                            &afl->dmsan_only_next_id);

  } else {

    afl->saved_msan_only = 0;
    afl->saved_dmsan_only = 0;
    afl->msan_only_next_id = 0;
    afl->dmsan_only_next_id = 0;

  }

}

static inline void dmsan_load_dedup_state_one(afl_state_t *afl,
                                              const char *name, u8 *map,
                                              size_t map_size) {

  if (!map || !map_size) { return; }

  u8 *path = alloc_printf("%s/%s", afl->out_dir, name);
  int fd = open((char *)path, O_RDONLY);

  if (fd < 0) {

    ck_free(path);
    return;

  }

  struct stat st;
  if (fstat(fd, &st) == 0 && st.st_size > 0) {

    size_t to_read = (size_t)st.st_size;
    if (to_read > map_size) { to_read = map_size; }
    ssize_t got = read(fd, map, to_read);
    (void)got;

  }

  close(fd);
  ck_free(path);

}

void dmsan_load_dedup_state(afl_state_t *afl) {

  dmsan_load_dedup_state_one(afl, ".dmsan_virgin", afl->virgin_dmsan,
                             afl->fsrv.map_size);
  dmsan_load_dedup_state_one(afl, ".msan_only_virgin", afl->virgin_msan_only,
                             afl->fsrv.map_size);
  dmsan_load_dedup_state_one(afl, ".dmsan_only_virgin",
                             afl->virgin_dmsan_only, afl->fsrv.map_size);
  if (afl->dmsan_aux_feedback && afl->dmsan_aux_compiled) {
    dmsan_load_dedup_state_one(
        afl, ".dmsan_aux_virgin", afl->virgin_dmsan_aux,
        sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }

}

static void dmsan_save_dedup_state_one(afl_state_t *afl, const char *name,
                                       const u8 *map, size_t map_size) {

  if (!map || !map_size) { return; }

  u8 *path = alloc_printf("%s/%s", afl->out_dir, name);
  int fd = open((char *)path, O_WRONLY | O_CREAT | O_TRUNC, afl->perm);

  if (fd < 0) {

    WARNF("Unable to persist DMSAN dedup state '%s'", path);
    ck_free(path);
    return;

  }

  if (afl->chown_needed) {

    if (fchown(fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  ck_write(fd, map, map_size, path);
  close(fd);
  ck_free(path);

}

static void dmsan_persist_dedup_state(afl_state_t *afl) {

  dmsan_save_dedup_state_one(afl, ".dmsan_virgin", afl->virgin_dmsan,
                             afl->fsrv.map_size);
  dmsan_save_dedup_state_one(afl, ".msan_only_virgin", afl->virgin_msan_only,
                             afl->fsrv.map_size);
  dmsan_save_dedup_state_one(afl, ".dmsan_only_virgin",
                             afl->virgin_dmsan_only, afl->fsrv.map_size);
  if (afl->dmsan_aux_feedback && afl->dmsan_aux_compiled) {
    dmsan_save_dedup_state_one(
        afl, ".dmsan_aux_virgin", afl->virgin_dmsan_aux,
        sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }

}

typedef enum {

  DMSAN_RUN1_READY = 0,
  DMSAN_RUN1_CLEAN_CACHE = 1,
  DMSAN_RUN1_CRASH = 2,
  DMSAN_RUN1_ERROR = 3,
  DMSAN_RUN1_TIMEOUT = 4,

} dmsan_run1_status_t;

static inline dmsan_run1_status_t dmsan_run1_prepare(afl_state_t *afl, u8 *buf,
                                                     u32 len, u64 *input_hash,
                                                     u64 *aux_cache_key) {

  afl->dmsan_last_aux_novelty = 0;
  afl->dmsan_last_aux_stable_sites = 0;
  afl->dmsan_last_aux_unstable_sites = 0;
  *input_hash = 0;
  *aux_cache_key = 0;

  if (dmsan_should_use_clean_cache(afl) && buf && len) {

    *input_hash = dmsan_clean_cache_hash(buf, len);
    if (dmsan_clean_cache_lookup(afl, buf, len, *input_hash)) {

      afl->dmsan_clean_cache_hits++;
      return DMSAN_RUN1_CLEAN_CACHE;

    }

  }

  u8 run_fault =
      dmsan_sample_run(afl, buf, len, DMSAN_POISON_RUN1, afl->dmsan_snapshot1,
                       afl->dmsan_aux_snapshot1);

  if (run_fault == FSRV_RUN_CRASH || run_fault == FSRV_RUN_ERROR) {

    afl->dmsan_current_finding.crash_run = 1;
    afl->dmsan_current_finding.crash_signal = afl->dmsan_fsrv.last_kill_signal;
    return (run_fault == FSRV_RUN_CRASH) ? DMSAN_RUN1_CRASH : DMSAN_RUN1_ERROR;

  }

  if (run_fault == FSRV_RUN_TMOUT) {
    return DMSAN_RUN1_TIMEOUT;
  }

  if (afl->dmsan_aux_cache && afl->dmsan_aux_compiled) {
    *aux_cache_key =
        dmsan_make_aux_cache_key(afl, afl->dmsan_aux_snapshot1);
  }
  /* Aux site_map novelty is scanned only when queue scoring consumes it.
     Nondeterminism recovery uses direct counter deltas instead. */
  if (afl->dmsan_aux_feedback && afl->dmsan_aux_compiled) {
    afl->dmsan_last_aux_novelty = dmsan_aux_has_new_bits(afl);
    if (afl->dmsan_last_aux_novelty) { afl->dmsan_aux_feedback_hits++; }
  }
  return DMSAN_RUN1_READY;

}

/* Pre-check before Run3: if all trace slots of the current input are already
   covered by saved DMSAN findings (virgin_dmsan), Run3 cannot produce a new
   unique finding and can be skipped.  Uses the DMSAN trace scratch buffer
   for simplification; safe because Run2 data is already in dmsan_snapshot2.
   This must not use has_new_bits_in(): that function destructively clears bits
   from the virgin map. This helper is a read-only scan that checks the same
   condition without modifying virgin_dmsan.
   Returns 1 if Run3 should be skipped, 0 if it must proceed. */
static inline u8 dmsan_precheck_run3(afl_state_t *afl) {

  if (unlikely(afl->non_instrumented_mode)) { return 0; }
  if (!afl->saved_dmsan_findings) { return 0; }

  u8 *dmsan_trace = dmsan_ensure_trace_scratch(afl, afl->fsrv.map_size);
  memcpy(dmsan_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);
  simplify_trace(afl, dmsan_trace);

#ifdef WORD_SIZE_64
  u32  i = (afl->fsrv.real_map_size + 7) >> 3;
  u64 *cur = (u64 *)dmsan_trace;
  u64 *vir = (u64 *)afl->virgin_dmsan;
#else
  u32  i = (afl->fsrv.real_map_size + 3) >> 2;
  u32 *cur = (u32 *)dmsan_trace;
  u32 *vir = (u32 *)afl->virgin_dmsan;
#endif

  while (i--) {
    if (*cur & *vir) { return 0; }  /* slot still virgin -> new finding possible */
    cur++;
    vir++;
  }
  return 1;  /* all slots already covered -> skip Run3 */

}

static fsrv_run_result_t dmsan_inline_run_with_retries(
    afl_state_t *afl, u8 **buf, u32 *len, u8 poison,
    struct dmsan_fast_map *snapshot, u16 *aux_snapshot) {

  fsrv_run_result_t ret = FSRV_RUN_ERROR;

  for (int attempt = 0; attempt < 3; ++attempt) {

    dmsan_set_poison(afl, poison);
    dmsan_clear_map(afl);
    dmsan_set_fixed_values(afl);
    *len = write_to_testcase(afl, (void **)buf, *len, 0);

    ret = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
    if (afl->fsrv.total_execs) { --afl->fsrv.total_execs; }
    if (ret != FSRV_RUN_TMOUT) { break; }

  }

  if (ret == FSRV_RUN_OK) {
    dmsan_save_snapshot(afl, snapshot);
    dmsan_save_aux_snapshot(afl, aux_snapshot);
  } else {
    dmsan_scrub_snapshot(snapshot, aux_snapshot);
  }

  memcpy(afl->fsrv.trace_bits, afl->dmsan_trace_backup, afl->fsrv.map_size);
  return ret;

}

/* Run one confirmation execution with the given poison value and snapshot
   the fast map into *snap.  Inline mode uses afl->fsrv (with trace backup/
   restore and exec-count correction); sidecar mode uses dmsan_sample_run.
   Returns FSRV_RUN_* as u8. */
static u8 dmsan_confirm_run_one(afl_state_t *afl, u8 *buf, u32 len, u8 poison,
                                struct dmsan_fast_map *snap, u16 *aux_snap) {

  if (afl->dmsan_inline_mode) {

    u8  *run_buf = buf;
    u32  run_len = len;
    afl->dmsan_checking = 1;
    u8 ret = (u8)dmsan_inline_run_with_retries(
        afl, &run_buf, &run_len, poison, snap, aux_snap);
    afl->dmsan_checking = 0;
    return ret;

  } else {

    return dmsan_sample_run(afl, buf, len, poison, snap, aux_snap);

  }

}

static dmsan_result_t dmsan_confirm_status_to_result(afl_state_t *afl,
                                                     u8 *buf, u32 len,
                                                     u8 ret) {

  if (ret == FSRV_RUN_CRASH || ret == FSRV_RUN_ERROR) {
    afl->dmsan_current_finding.crash_run = 10;
    afl->dmsan_current_finding.crash_signal =
        afl->dmsan_inline_mode ? afl->fsrv.last_kill_signal
                               : afl->dmsan_fsrv.last_kill_signal;
    ++afl->dmsan_crashes;
    return DMSAN_CRASH;
  }
  if (ret == FSRV_RUN_TMOUT) { return dmsan_timeout_result(afl, buf, len, 10); }
  if (ret != FSRV_RUN_OK) { return DMSAN_NON_DETERMINISTIC; }
  return DMSAN_BUG_FOUND;

}

/* Run a confirmation triplet (0x11, 0x11, 0x22):
 *   confA == confB  - determinism under same poison
 *   confA != confC  - sensitivity to different poison
 * Returns DMSAN_BUG_FOUND if both hold, DMSAN_NON_DETERMINISTIC otherwise,
 * DMSAN_TIMEOUT if any confirmation run times out, or DMSAN_CRASH if any
 * confirmation run crashes (crash_run set to 10). */
static dmsan_result_t dmsan_run_confirm_triplet(afl_state_t *afl, u8 *buf,
                                                u32 len) {

  struct dmsan_fast_map ca, cb, cc;

  u8 r = dmsan_confirm_run_one(afl, buf, len, DMSAN_POISON_RUN1, &ca, NULL);
  if (r == FSRV_RUN_CRASH || r == FSRV_RUN_ERROR) {
    afl->dmsan_current_finding.crash_run = 10;  /* confirm phase */
    afl->dmsan_current_finding.crash_signal =
        afl->dmsan_inline_mode ? afl->fsrv.last_kill_signal
                               : afl->dmsan_fsrv.last_kill_signal;
    ++afl->dmsan_crashes;
    return DMSAN_CRASH;
  }
  if (r == FSRV_RUN_TMOUT) { return dmsan_timeout_result(afl, buf, len, 10); }
  if (r != FSRV_RUN_OK) { return DMSAN_NON_DETERMINISTIC; }

  r = dmsan_confirm_run_one(afl, buf, len, DMSAN_POISON_RUN1, &cb, NULL);
  if (r == FSRV_RUN_CRASH || r == FSRV_RUN_ERROR) {
    afl->dmsan_current_finding.crash_run = 10;
    afl->dmsan_current_finding.crash_signal =
        afl->dmsan_inline_mode ? afl->fsrv.last_kill_signal
                               : afl->dmsan_fsrv.last_kill_signal;
    ++afl->dmsan_crashes;
    return DMSAN_CRASH;
  }
  if (r == FSRV_RUN_TMOUT) { return dmsan_timeout_result(afl, buf, len, 10); }
  if (r != FSRV_RUN_OK) { return DMSAN_NON_DETERMINISTIC; }

  if (!dmsan_signatures_equal(&ca, &cb)) { return DMSAN_NON_DETERMINISTIC; }

  r = dmsan_confirm_run_one(afl, buf, len, DMSAN_POISON_RUN2, &cc, NULL);
  if (r == FSRV_RUN_CRASH || r == FSRV_RUN_ERROR) {
    afl->dmsan_current_finding.crash_run = 10;
    afl->dmsan_current_finding.crash_signal =
        afl->dmsan_inline_mode ? afl->fsrv.last_kill_signal
                               : afl->dmsan_fsrv.last_kill_signal;
    ++afl->dmsan_crashes;
    return DMSAN_CRASH;
  }
  if (r == FSRV_RUN_TMOUT) { return dmsan_timeout_result(afl, buf, len, 10); }
  if (r != FSRV_RUN_OK) { return DMSAN_NON_DETERMINISTIC; }

  if (dmsan_signatures_equal(&ca, &cc)) { return DMSAN_NON_DETERMINISTIC; }

  return DMSAN_BUG_FOUND;

}

static dmsan_result_t dmsan_run_confirm_aux_triplet(afl_state_t *afl, u8 *buf,
                                                    u32 len) {

  if (!afl->dmsan_aux_compiled) { return DMSAN_CLEAN; }

  u16 *a = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  u16 *b = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  u16 *c = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);

  u8 r = dmsan_confirm_run_one(afl, buf, len, DMSAN_POISON_RUN1, NULL, a);
  dmsan_result_t status = dmsan_confirm_status_to_result(afl, buf, len, r);
  if (status != DMSAN_BUG_FOUND) { goto done_status; }

  r = dmsan_confirm_run_one(afl, buf, len, DMSAN_POISON_RUN1, NULL, b);
  status = dmsan_confirm_status_to_result(afl, buf, len, r);
  if (status != DMSAN_BUG_FOUND) { goto done_status; }

  r = dmsan_confirm_run_one(afl, buf, len, DMSAN_POISON_RUN2, NULL, c);
  status = dmsan_confirm_status_to_result(afl, buf, len, r);
  if (status != DMSAN_BUG_FOUND) { goto done_status; }

  /* Confirmation runs are ordered Run1, Run1, Run2; the aux verdict expects
     Run1, Run2, Run3, so the same-poison second run is the Run3 argument. */
  status = dmsan_aux_compute_verdict_for_maps(a, c, b);

done_status:
  ck_free(a);
  ck_free(b);
  ck_free(c);
  return status;

}

static void dmsan_save_confirm_reject_debug(afl_state_t *afl, u8 *buf, u32 len,
                                            dmsan_result_t verdict,
                                            u64 reject_id) {

  u8 *input_fn = alloc_printf(
      "%s/dmsan_findings/confirm_reject_input_%06llu_%s", afl->out_dir,
      (unsigned long long)reject_id, dmsan_result_name(verdict));
  s32 fd = open((char *)input_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd >= 0) {
    ck_write(fd, buf, len, input_fn);
    close(fd);

    u8 *sig_fn = alloc_printf("%s.sig", input_fn);
    dmsan_write_sig_sidecar(afl, (const char *)sig_fn, verdict,
                            afl->dmsan_snapshot1, afl->dmsan_snapshot2,
                            afl->dmsan_snapshot3);
    ck_free(sig_fn);
  }
  ck_free(input_fn);

}

/* After 3-run protocol concludes with BUG_FOUND: run up to dmsan_confirm_runs
   confirmation triplets before committing.  On all pass: increments
   dmsan_aux_rescues (if is_aux_rescue), dmsan_bugs_found, and returns
   DMSAN_BUG_FOUND.  On rejection: increments dmsan_confirm_rejected and
   returns the triplet verdict (DMSAN_NON_DETERMINISTIC, DMSAN_TIMEOUT, or
   DMSAN_CRASH). */
static dmsan_result_t dmsan_try_confirm(afl_state_t *afl, u8 *buf, u32 len,
                                        u8 is_aux_rescue) {

  for (u32 i = 0; i < afl->dmsan_confirm_runs; ++i) {
    dmsan_result_t v = is_aux_rescue
                           ? dmsan_run_confirm_aux_triplet(afl, buf, len)
                           : dmsan_run_confirm_triplet(afl, buf, len);
    if (v != DMSAN_BUG_FOUND) {
      ++afl->dmsan_confirm_rejected;
      if (v != DMSAN_TIMEOUT && afl->dmsan_save_nondet &&
          afl->dmsan_confirm_rejected <= 20) {
        dmsan_save_confirm_reject_debug(afl, buf, len, v,
                                        afl->dmsan_confirm_rejected);
      }
      return v;
    }
  }
  if (is_aux_rescue) { ++afl->dmsan_aux_rescues; }
  ++afl->dmsan_bugs_found;
  return DMSAN_BUG_FOUND;

}

/* Resolve the one Run1/Run2/Run3 triplet. QDMSan evaluates each memory-error
   plane independently: a stable plane is a confirmed bug even when another
   candidate plane is nondeterministic. LLVM DMSan retains its historical
   global-signature/aux behavior. */
static dmsan_result_t dmsan_finish_triplet(afl_state_t *afl, u8 *buf,
                                           u32 len) {

  if (afl->qdmsan_enabled) {
    struct qdmsan_plane_verdict planes = qdmsan_classify_triplet(
        afl->dmsan_snapshot1, afl->dmsan_snapshot2, afl->dmsan_snapshot3);
    afl->dmsan_current_finding.candidate_mask = planes.candidate_mask;
    afl->dmsan_current_finding.confirmed_mask = planes.confirmed_mask;
    afl->dmsan_current_finding.nondet_mask = planes.nondet_mask;
  }

  if (!dmsan_active_triplet_complete(
          afl, afl->dmsan_snapshot1, afl->dmsan_snapshot2,
          afl->dmsan_snapshot3)) {
    if (afl->debug) {
      DEBUGF("DMSAN finding candidate dropped due to empty checkpoints: "
             "run1=(%llu,%llu,%llu) run2=(%llu,%llu,%llu) "
             "run3=(%llu,%llu,%llu)\n",
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot1, QDMSAN_PLANE_UUM),
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot1, QDMSAN_PLANE_OOB),
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot1, QDMSAN_PLANE_UAF),
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot2, QDMSAN_PLANE_UUM),
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot2, QDMSAN_PLANE_OOB),
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot2, QDMSAN_PLANE_UAF),
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot3, QDMSAN_PLANE_UUM),
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot3, QDMSAN_PLANE_OOB),
             (unsigned long long)qdmsan_plane_count(
                 afl->dmsan_snapshot3, QDMSAN_PLANE_UAF));
    }
    return DMSAN_CLEAN;
  }

  if (afl->qdmsan_enabled) {
    if (afl->dmsan_current_finding.confirmed_mask) {
      ++afl->dmsan_bugs_found;
      return DMSAN_BUG_FOUND;
    }
    if (afl->dmsan_current_finding.nondet_mask) {
      ++afl->dmsan_nondets;
      if (afl->dmsan_save_nondet && afl->dmsan_nondets <= 20) {
        dmsan_save_nondet_debug(afl, buf, len);
      }
      return DMSAN_NON_DETERMINISTIC;
    }
    return DMSAN_CLEAN;
  }

  /* Compiler-based DMSan: preserve the existing global semantic verdict and
     optional per-site aux rescue. */
  if (!dmsan_signatures_equal(afl->dmsan_snapshot1,
                              afl->dmsan_snapshot3)) {
    dmsan_analyze_aux_nondet(afl);

    if (afl->dmsan_aux_nondet && afl->dmsan_aux_compiled) {
      dmsan_result_t aux_v = dmsan_aux_compute_verdict(afl);
      if (aux_v == DMSAN_BUG_FOUND) {
        return dmsan_try_confirm(afl, buf, len, 1);
      }
    }

    ++afl->dmsan_nondets;
    if (afl->dmsan_save_nondet && afl->dmsan_nondets <= 20) {
      dmsan_save_nondet_debug(afl, buf, len);
    }
    return DMSAN_NON_DETERMINISTIC;
  }

  return dmsan_try_confirm(afl, buf, len, 0);

}

static inline dmsan_result_t dmsan_complete_check_from_run1(afl_state_t *afl,
                                                            u8 *buf, u32 len,
                                                            u64 input_hash,
                                                            u64 l2_key,
                                                            u8 allow_l2) {

  if (allow_l2 && afl->dmsan_aux_cache && dmsan_aux_cache_lookup_clean(afl, l2_key)) {
    return DMSAN_CLEAN;
  }

  /* === Run 2: poison=0x22 (detect uninit memory) === */
  u8 run_fault =
      dmsan_sample_run(afl, buf, len, DMSAN_POISON_RUN2, afl->dmsan_snapshot2,
                       afl->dmsan_aux_snapshot2);

  if (run_fault == FSRV_RUN_CRASH || run_fault == FSRV_RUN_ERROR) {

    afl->dmsan_current_finding.crash_run = 2;
    afl->dmsan_current_finding.crash_signal = afl->dmsan_fsrv.last_kill_signal;
    afl->dmsan_crashes++;
    return DMSAN_CRASH;

  }

  if (run_fault == FSRV_RUN_TMOUT) {
    return dmsan_timeout_result(afl, buf, len, 2);
  }

  if (afl->debug) {
    DEBUGF("DMSAN Run2: sum=0x%016llx rotl=0x%016llx cnt=%llu\n",
           (unsigned long long)afl->dmsan_snapshot2->sum_signature,
           (unsigned long long)afl->dmsan_snapshot2->rotl_signature,
           (unsigned long long)afl->dmsan_snapshot2->total_count);
  }

  if (dmsan_active_signatures_equal(afl, afl->dmsan_snapshot1,
                                    afl->dmsan_snapshot2)) {

    if (dmsan_should_use_clean_cache(afl) && buf && len) {
      dmsan_clean_cache_insert(afl, buf, len, input_hash);
    }
    if (allow_l2 && afl->dmsan_aux_cache) { dmsan_aux_cache_insert_clean(afl, l2_key); }
    return DMSAN_CLEAN;

  }

  if (!afl->qdmsan_enabled && afl->dmsan_run3_dedup &&
      dmsan_precheck_run3(afl)) {
    ++afl->dmsan_deduped_runs;
    return DMSAN_DEDUPED;
  }

  /* === Run 3: poison=0x11 (non-determinism check, only on diff) === */
  run_fault =
      dmsan_sample_run(afl, buf, len, DMSAN_POISON_RUN3, afl->dmsan_snapshot3,
                       afl->dmsan_aux_snapshot3);

  if (run_fault == FSRV_RUN_CRASH || run_fault == FSRV_RUN_ERROR) {

    afl->dmsan_current_finding.crash_run = 3;
    afl->dmsan_current_finding.crash_signal = afl->dmsan_fsrv.last_kill_signal;
    afl->dmsan_crashes++;
    return DMSAN_CRASH;

  }

  if (run_fault == FSRV_RUN_TMOUT) {
    return dmsan_timeout_result(afl, buf, len, 3);
  }

  if (afl->debug) {
    DEBUGF("DMSAN Run3: sum=0x%016llx rotl=0x%016llx cnt=%llu\n",
           (unsigned long long)afl->dmsan_snapshot3->sum_signature,
           (unsigned long long)afl->dmsan_snapshot3->rotl_signature,
           (unsigned long long)afl->dmsan_snapshot3->total_count);
  }

  return dmsan_finish_triplet(afl, buf, len);

}

static inline u8 dmsan_should_probe_feedback(afl_state_t *afl, u64 trace_cksum) {

  if (!afl->dmsan_probe_counts) { return 0; }

  u32 slot = trace_cksum % N_FUZZ_SIZE;
  u8 count = afl->dmsan_probe_counts[slot];
  if (count != 0xff) { ++count; }
  afl->dmsan_probe_counts[slot] = count;

  if (count <= 4) { return 1; }
  return (count & (count - 1)) == 0;

}

static inline u8 dmsan_clean_cache_lookup(afl_state_t *afl, u8 *buf, u32 len,
                                          u64 input_hash) {

  if (!afl->dmsan_clean_cache || !buf || !len) { return 0; }

  for (u32 i = 0; i < afl->dmsan_clean_cache_max; ++i) {

    struct dmsan_clean_cache_entry *entry = &afl->dmsan_clean_cache[i];
    if (!entry->buf) { continue; }
    if (entry->hash != input_hash || entry->len != len) { continue; }
    if (!memcmp(entry->buf, buf, len)) { return 1; }

  }

  return 0;

}

static inline void dmsan_clean_cache_insert(afl_state_t *afl, u8 *buf, u32 len,
                                            u64 input_hash) {

  if (!afl->dmsan_clean_cache || !buf || !len) { return; }

  struct dmsan_clean_cache_entry *slot = NULL;

  for (u32 i = 0; i < afl->dmsan_clean_cache_max; ++i) {

    struct dmsan_clean_cache_entry *entry = &afl->dmsan_clean_cache[i];
    if (!entry->buf) {

      if (!slot) { slot = entry; }
      continue;

    }

    if (entry->hash == input_hash && entry->len == len &&
        !memcmp(entry->buf, buf, len)) {
      return;
    }

  }

  if (!slot) {

    slot = &afl->dmsan_clean_cache[afl->dmsan_clean_cache_next];
    afl->dmsan_clean_cache_next =
        (afl->dmsan_clean_cache_next + 1) % afl->dmsan_clean_cache_max;
    if (slot->buf) {

      ck_free(slot->buf);
      slot->buf = NULL;

    }

  }

  slot->buf = ck_alloc_nozero(len);
  memcpy(slot->buf, buf, len);
  slot->len = len;
  slot->hash = input_hash;
  afl->dmsan_clean_cache_inserts++;

}

/* ========== Initialization ========== */

void dmsan_setup_shm(afl_state_t *afl) {

  afl->dmsan_shm_sitemap_id = -1;
  afl->dmsan_shm_sitemap_ptr = NULL;
  afl->dmsan_sitemap = NULL;
  afl->dmsan_sitemap_count = 0;
  afl->dmsan_shm_feedback_id = -1;
  afl->dmsan_shm_feedback = NULL;
  afl->dmsan_shm_full_id = -1;
  afl->dmsan_shm_full = NULL;

  /* Create Fast mode shared memory (128 bytes) */
  afl->dmsan_shm_fast_id =
      shmget(IPC_PRIVATE, sizeof(struct dmsan_fast_map), IPC_CREAT | 0600);

  if (afl->dmsan_shm_fast_id < 0) {

    PFATAL("shmget() for DMSAN fast map failed");

  }

  afl->dmsan_shm_fast = shmat(afl->dmsan_shm_fast_id, NULL, 0);
  if (afl->dmsan_shm_fast == (void *)-1) {

    shmctl(afl->dmsan_shm_fast_id, IPC_RMID, NULL);
    PFATAL("shmat() for DMSAN fast map failed");

  }

  shmctl(afl->dmsan_shm_fast_id, IPC_RMID, NULL);

  memset(afl->dmsan_shm_fast, 0, sizeof(struct dmsan_fast_map));

  if (afl->dmsan_aux_compiled) {

    /* Create aux site-class shared memory only for fast+aux runtime roles. */
    afl->dmsan_shm_feedback_id =
        shmget(IPC_PRIVATE, sizeof(struct dmsan_feedback_shm), IPC_CREAT | 0600);

    if (afl->dmsan_shm_feedback_id < 0) {

      PFATAL("shmget() for DMSAN feedback map failed");

    }

    afl->dmsan_shm_feedback = shmat(afl->dmsan_shm_feedback_id, NULL, 0);
    if (afl->dmsan_shm_feedback == (void *)-1) {

      shmctl(afl->dmsan_shm_feedback_id, IPC_RMID, NULL);
      PFATAL("shmat() for DMSAN feedback map failed");

    }

    shmctl(afl->dmsan_shm_feedback_id, IPC_RMID, NULL);

    memset(afl->dmsan_shm_feedback, 0, sizeof(struct dmsan_feedback_shm));
    ((struct dmsan_feedback_shm *)afl->dmsan_shm_feedback)->header.magic =
        DMSAN_FEEDBACK_MAGIC;
    ((struct dmsan_feedback_shm *)afl->dmsan_shm_feedback)->header.version =
        DMSAN_FEEDBACK_VERSION;
    ((struct dmsan_feedback_shm *)afl->dmsan_shm_feedback)->header.map_size =
        DMSAN_FEEDBACK_MAP_SIZE;
    ((struct dmsan_feedback_shm *)afl->dmsan_shm_feedback)
        ->header.site_map_entries = DMSAN_SITE_CLASS_ENTRIES;

  }

  if (afl->dmsan_full_mode) {

    u32 full_entries = DMSAN_FULL_MIN_SIZE;
    const char *full_size_env = getenv("AFL_QDMSAN_FULL_SIZE");
    if (full_size_env && *full_size_env) {
      errno = 0;
      char *end = NULL;
      unsigned long parsed = strtoul(full_size_env, &end, 10);
      if (errno || !end || *end) {
        FATAL("AFL_QDMSAN_FULL_SIZE: expected an entry count, got '%s'",
              full_size_env);
      }
      full_entries = (u32)parsed;
      if (full_entries < DMSAN_FULL_MIN_SIZE) {
        full_entries = DMSAN_FULL_MIN_SIZE;
      }
      if (full_entries > DMSAN_FULL_MAX_SIZE) {
        full_entries = DMSAN_FULL_MAX_SIZE;
      }
    }
    if (full_entries & (full_entries - 1)) {
      u32 rounded = DMSAN_FULL_MIN_SIZE;
      while (rounded < full_entries && rounded < DMSAN_FULL_MAX_SIZE) {
        rounded <<= 1;
      }
      full_entries = rounded;
    }

    size_t full_size = sizeof(struct dmsan_full_meta) +
                       (size_t)full_entries * sizeof(struct dmsan_full_entry);
    afl->dmsan_shm_full_id =
        shmget(IPC_PRIVATE, full_size, IPC_CREAT | 0600);
    if (afl->dmsan_shm_full_id < 0) {
      PFATAL("shmget() for DMSAN full map failed");
    }
    afl->dmsan_shm_full = shmat(afl->dmsan_shm_full_id, NULL, 0);
    if (afl->dmsan_shm_full == (void *)-1) {
      shmctl(afl->dmsan_shm_full_id, IPC_RMID, NULL);
      PFATAL("shmat() for DMSAN full map failed");
    }
    shmctl(afl->dmsan_shm_full_id, IPC_RMID, NULL);
    memset(afl->dmsan_shm_full, 0, full_size);
    struct dmsan_full_shm *full =
        (struct dmsan_full_shm *)afl->dmsan_shm_full;
    full->meta.magic = DMSAN_FULL_MAGIC;
    full->meta.array_size = full_entries;
    full->meta.mode = DMSAN_FULL_MODE_HASH;
    full->meta.abi_version = DMSAN_FULL_ABI_VERSION;

  }

  /* Create poison byte shared memory (1 byte) */
  afl->dmsan_shm_poison_id = shmget(IPC_PRIVATE, 1, IPC_CREAT | 0600);

  if (afl->dmsan_shm_poison_id < 0) {

    PFATAL("shmget() for DMSAN poison byte failed");

  }

  afl->dmsan_shm_poison = shmat(afl->dmsan_shm_poison_id, NULL, 0);
  if (afl->dmsan_shm_poison == (void *)-1) {

    shmctl(afl->dmsan_shm_poison_id, IPC_RMID, NULL);
    PFATAL("shmat() for DMSAN poison byte failed");

  }

  shmctl(afl->dmsan_shm_poison_id, IPC_RMID, NULL);

  *afl->dmsan_shm_poison = DMSAN_POISON_RUN1;

  /* Sitemap SHM for full-mode file:line metadata.
   * Fast mode will ignore the env var; full mode ctor will populate it. */
  size_t sitemap_size =
      DMSAN_SITEMAP_MAX_ENTRIES * sizeof(struct dmsan_sitemap_entry);
  afl->dmsan_shm_sitemap_id =
      shmget(IPC_PRIVATE, sitemap_size, IPC_CREAT | 0600);
  if (afl->dmsan_shm_sitemap_id < 0) {

    WARNF("shmget() for DMSAN sitemap failed, file:line reporting disabled");
    afl->dmsan_shm_sitemap_id = -1;

  } else {

    afl->dmsan_shm_sitemap_ptr =
        (struct dmsan_sitemap_entry *)shmat(afl->dmsan_shm_sitemap_id, NULL, 0);
    if (afl->dmsan_shm_sitemap_ptr == (void *)-1) {

      WARNF("shmat() for DMSAN sitemap failed, file:line reporting disabled");
      shmctl(afl->dmsan_shm_sitemap_id, IPC_RMID, NULL);
      afl->dmsan_shm_sitemap_id = -1;
      afl->dmsan_shm_sitemap_ptr = NULL;

    } else {

      memset(afl->dmsan_shm_sitemap_ptr, 0, sitemap_size);
      shmctl(afl->dmsan_shm_sitemap_id, IPC_RMID, NULL);

    }

  }

  /* Allocate local snapshot memory */
  afl->dmsan_snapshot1 = ck_alloc(sizeof(struct dmsan_fast_map));
  afl->dmsan_snapshot2 = ck_alloc(sizeof(struct dmsan_fast_map));
  afl->dmsan_snapshot3 = ck_alloc(sizeof(struct dmsan_fast_map));
  afl->dmsan_cal_sig1 = ck_alloc(sizeof(struct dmsan_fast_map));
  afl->dmsan_cal_sig2 = ck_alloc(sizeof(struct dmsan_fast_map));
  afl->dmsan_cal_aux1 =
      ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  afl->dmsan_cal_aux2 =
      ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  if (afl->dmsan_aux_compiled) {
    afl->dmsan_aux_snapshot1 =
        ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
    afl->dmsan_aux_snapshot2 =
        ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
    afl->dmsan_aux_snapshot3 =
        ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }

  /* Capture fixed values for deterministic execution */
  struct timeval tv;
  gettimeofday(&tv, NULL);
  afl->dmsan_fixed_time_sec = (u64)tv.tv_sec;
  afl->dmsan_fixed_time_usec = (u64)tv.tv_usec;

  srand((unsigned)(tv.tv_sec ^ tv.tv_usec ^ getpid()));
  afl->dmsan_fixed_rand_base = dmsan_rand_u64();

  /* Capture TSC base value */
#if defined(__x86_64__) || defined(__i386__)
  {

    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    afl->dmsan_fixed_tsc_base = ((u64)hi << 32) | lo;

  }

#else
  afl->dmsan_fixed_tsc_base =
      (u64)tv.tv_sec * 1000000000ULL + (u64)tv.tv_usec * 1000ULL;
#endif

  /* Match LLVM DMSAN's dmsanfork-diff: fixed_rdrand_base deliberately uses
     the runner PRNG fallback, not hardware rdrand, so the seed path works on
     older x86 hosts and remains replayable through the same env override. */
  afl->dmsan_fixed_rdrand_base = dmsan_rand_u64();

  u8 replay_overrides = 0;
  if (dmsan_should_apply_replay_overrides()) {
    replay_overrides += dmsan_read_replay_u64("FIXED_TIME_SEC",
                                              &afl->dmsan_fixed_time_sec);
    replay_overrides += dmsan_read_replay_u64("FIXED_TIME_USEC",
                                              &afl->dmsan_fixed_time_usec);
    replay_overrides += dmsan_read_replay_u64("FIXED_RAND_BASE",
                                              &afl->dmsan_fixed_rand_base);
    replay_overrides += dmsan_read_replay_u64("FIXED_TSC_BASE",
                                              &afl->dmsan_fixed_tsc_base);
    replay_overrides += dmsan_read_replay_u64("FIXED_RDRAND_BASE",
                                              &afl->dmsan_fixed_rdrand_base);
  }

  if (afl->debug) {
    DEBUGF(
        "DMSAN shared memory initialized (fast_id=%d, feedback_id=%d, poison_id=%d, sitemap_id=%d)\n",
        afl->dmsan_shm_fast_id, afl->dmsan_shm_feedback_id,
        afl->dmsan_shm_poison_id, afl->dmsan_shm_sitemap_id);
    if (replay_overrides) {
      DEBUGF("DMSAN replay fixed-value overrides applied: %u\n",
             replay_overrides);
    }
    if (afl->dmsan_debug_enabled) {
      DEBUGF("DMSAN debug artifacts enabled (sig_sidecars=%u, saved_inputs=%u)\n",
             afl->dmsan_debug_dump_sig, afl->dmsan_save_nondet);
    }
  }

}

void dmsan_read_sitemap(afl_state_t *afl) {

  if (!afl->dmsan_shm_sitemap_ptr || afl->dmsan_sitemap_count) { return; }

  u32 count = 0;
  while (count < DMSAN_SITEMAP_MAX_ENTRIES &&
         afl->dmsan_shm_sitemap_ptr[count].site_id != 0) {
    ++count;
  }

  if (!count) { return; }

  if (afl->dmsan_sitemap) {
    ck_free(afl->dmsan_sitemap);
    afl->dmsan_sitemap = NULL;
  }

  afl->dmsan_sitemap =
      ck_alloc(count * sizeof(struct dmsan_sitemap_entry));
  memcpy(afl->dmsan_sitemap, afl->dmsan_shm_sitemap_ptr,
         count * sizeof(struct dmsan_sitemap_entry));
  afl->dmsan_sitemap_count = count;

  OKF("DMSAN: sitemap loaded (%u checkpoints, file:line reporting enabled)",
      count);

}

void dmsan_init(afl_state_t *afl) {

  dmsan_read_config(afl);

  if (!afl->dmsan_binary && !afl->qdmsan_enabled) { return; }

  if (afl->qdmsan_enabled) {
    if (afl->dmsan_binary) {
      FATAL("AFL_QDMSAN_MODE uses the main -Q target as the sidecar; do not "
            "combine it with -j");
    }
    if (!afl->fsrv.qemu_mode) {
      FATAL("AFL_QDMSAN_MODE requires QEMU mode (-Q)");
    }
    setenv("AFL_USE_QDMSAN", "1", 1);
  }

  if (afl->dmsan_inline_mode) {
    FATAL("AFL_DMSAN_DEPLOY=inline is incompatible with -j secondary "
          "DMSAN (sidecar binary)");
  }

  if (afl->debug) {
    DEBUGF("Initializing %s with target: %s\n",
           afl->qdmsan_enabled ? "QDMSAN" : "DMSAN",
           afl->qdmsan_enabled ? (char *)afl->fsrv.target_path
                                : afl->dmsan_binary);
  }

  /* Create dmsan_findings directory */
  u8 *dmsan_dir = alloc_printf("%s/dmsan_findings", afl->out_dir);
  if (mkdir((char *)dmsan_dir, 0700) && errno != EEXIST) {

    PFATAL("Unable to create '%s'", dmsan_dir);

  }

  ck_free(dmsan_dir);

  if (afl->san_binary_length) {

    u8 *msan_only_dir = alloc_printf("%s/msan_only", afl->out_dir);
    if (mkdir((char *)msan_only_dir, 0700) && errno != EEXIST) {
      PFATAL("Unable to create '%s'", msan_only_dir);
    }
    ck_free(msan_only_dir);

    u8 *dmsan_only_dir = alloc_printf("%s/dmsan_only", afl->out_dir);
    if (mkdir((char *)dmsan_only_dir, 0700) && errno != EEXIST) {
      PFATAL("Unable to create '%s'", dmsan_only_dir);
    }
    ck_free(dmsan_only_dir);

  }

  dmsan_recover_findings_state(afl);

  /* Setup DMSAN shared memory (signatures and poison byte) */
  dmsan_setup_shm(afl);

  /* Set environment variables for child process BEFORE forkserver starts.
     DMSAN runtime will detect AFL++ mode via these env vars and attach
     shared memory at its fixed address (0x7f0000000000). */
  char shm_fast_str[32], shm_feedback_str[32], shm_full_str[32],
      shm_poison_str[32],
      shm_sitemap_str[32],
      map_size_str[32];
  snprintf(shm_fast_str, sizeof(shm_fast_str), "%d", afl->dmsan_shm_fast_id);
  snprintf(shm_poison_str, sizeof(shm_poison_str), "%d",
           afl->dmsan_shm_poison_id);
  setenv(DMSAN_FAST_SHM_ENV_VAR, shm_fast_str, 1);
  if (afl->dmsan_shm_feedback_id >= 0) {
    snprintf(shm_feedback_str, sizeof(shm_feedback_str), "%d",
             afl->dmsan_shm_feedback_id);
    setenv(DMSAN_FEEDBACK_SHM_ENV_VAR, shm_feedback_str, 1);
  } else {
    unsetenv(DMSAN_FEEDBACK_SHM_ENV_VAR);
  }
  if (afl->dmsan_shm_full_id >= 0) {
    snprintf(shm_full_str, sizeof(shm_full_str), "%d",
             afl->dmsan_shm_full_id);
    setenv(DMSAN_FULL_SHM_ENV_VAR, shm_full_str, 1);
  } else {
    unsetenv(DMSAN_FULL_SHM_ENV_VAR);
  }
  setenv(DMSAN_POISON_SHM_ENV_VAR, shm_poison_str, 1);
  if (afl->dmsan_shm_sitemap_id >= 0) {
    snprintf(shm_sitemap_str, sizeof(shm_sitemap_str), "%d",
             afl->dmsan_shm_sitemap_id);
    setenv(DMSAN_SITEMAP_SHM_ENV_VAR, shm_sitemap_str, 1);
  }

  /* Set AFL_MAP_SIZE to match what the DMSAN sidecar binary reports.
     A sidecar build (AFL_DMSAN_DEPLOY=sidecar, the default) is sanitizer-only
     and reports MAP_SIZE, independent of the coverage target's real map. */
  u32 dmsan_map_size = MAP_SIZE;  /* 65536 - matches binary's default */
  snprintf(map_size_str, sizeof(map_size_str), "%u", dmsan_map_size);
  setenv("AFL_MAP_SIZE", map_size_str, 1);

  /* Initialize the DMSAN forkserver (following SAND pattern from sanfuzz) */
  afl_fsrv_init_dup(&afl->dmsan_fsrv, &afl->fsrv);

  /* Set the map_size for DMSAN forkserver to match */
  afl->dmsan_fsrv.map_size = dmsan_map_size;

  /* Allocate separate trace_bits for DMSAN forkserver.
     We don't actually use coverage from DMSAN binary, but forkserver
     infrastructure expects trace_bits to be allocated. */
  afl->dmsan_fsrv.trace_bits =
      ck_alloc(dmsan_map_size + 8);  /* +8 for alignment like afl_shm_init */

  /* Mark as sanitizer-only (no coverage instrumentation).  This is the same
     SAND-sidecar pattern used for ASAN/MSAN; for DMSAN it is selected by
     compiling with AFL_DMSAN_MODE=fast or fast+aux and DEPLOY=sidecar. */
  afl->dmsan_fsrv.san_but_not_instrumented = 1;

  /* Set target to DMSAN binary, or to the existing afl-qemu-trace binary for
     QDMSAN. In QEMU mode argv already has: afl-qemu-trace -- target ... */
  afl->dmsan_fsrv.target_path =
      afl->qdmsan_enabled ? afl->fsrv.target_path : (u8 *)afl->dmsan_binary;

  /* Use DMSAN-specific exec child function */
  afl->dmsan_fsrv.init_child_func = dmsan_exec_child;

  /* Share the same output file as main forkserver */
  afl->dmsan_fsrv.out_file = afl->fsrv.out_file;

  /* Copy mode settings from main forkserver */
  afl->dmsan_fsrv.cs_mode = afl->fsrv.cs_mode;
  afl->dmsan_fsrv.qemu_mode = afl->fsrv.qemu_mode;
  afl->dmsan_fsrv.frida_mode = afl->fsrv.frida_mode;

  /* Allocate bitmap for simplified trace deduplication (like SAND's
   * simplified_n_fuzz). This allows DMSAN to trigger on unique simplified
   * traces, not just on new coverage bits. */
  afl->dmsan_n_fuzz = ck_alloc(N_FUZZ_SIZE_BITMAP * sizeof(u8));

  /* Allocate virgin_dmsan bitmap for uniqueness tracking (like virgin_crash).
   * Must use DEFAULT_SHMEM_SIZE (same as virgin_bits initial allocation).
   *
   * The local map_size in main() starts at get_map_size() = DEFAULT_SHMEM_SIZE
   * (8MB) and only ever GROWS via afl_resize_map_buffers(). The memset at
   * afl-fuzz.c:3160 uses this local map_size. So virgin_dmsan must be at
   * least DEFAULT_SHMEM_SIZE bytes. Using MAP_SIZE (65536) or
   * afl->fsrv.map_size (actual edge count, can be tiny) both cause overflow. */
  afl->virgin_dmsan = ck_alloc(DEFAULT_SHMEM_SIZE);
  if (afl->san_binary_length) {
    afl->virgin_msan_only = ck_alloc(DEFAULT_SHMEM_SIZE);
    afl->virgin_dmsan_only = ck_alloc(DEFAULT_SHMEM_SIZE);
  }
  if (afl->dmsan_aux_compiled) {
    afl->virgin_dmsan_aux =
        ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
    memset(afl->virgin_dmsan_aux, 0xff,
           sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }
  if (afl->dmsan_clean_cache_enabled) {
    afl->dmsan_clean_cache_max = DMSAN_CLEAN_CACHE_DEFAULT_ENTRIES;
    afl->dmsan_clean_cache =
        ck_alloc(sizeof(struct dmsan_clean_cache_entry) *
                 afl->dmsan_clean_cache_max);
    afl->dmsan_clean_cache_next = 0;
  }
  afl->dmsan_probe_counts = ck_alloc_nozero(N_FUZZ_SIZE);
  dmsan_alloc_aux_cache(afl);

  afl->dmsan_enabled = 1;

  if (afl->debug) {
    DEBUGF("DMSAN initialized (san_but_not_instrumented=1, shm_fast_id=%d, "
           "shm_feedback_id=%d, shm_poison_id=%d)\n",
           afl->dmsan_shm_fast_id, afl->dmsan_shm_feedback_id,
           afl->dmsan_shm_poison_id);
  }

}

void dmsan_integrated_init(afl_state_t *afl) {

  dmsan_read_config(afl);
  afl->dmsan_inline_mode = 1;

  if (afl->qdmsan_enabled) {
    if (!afl->fsrv.qemu_mode) {
      FATAL("AFL_QDMSAN_DEPLOY=inline requires QEMU mode (-Q)");
    }
    setenv("AFL_USE_QDMSAN", "1", 1);
  }

  if (afl->dmsan_binary) {
    FATAL("AFL_DMSAN_DEPLOY=inline is incompatible with -j secondary DMSAN "
          "(inline reuses the main fsrv binary)");
  }

  u8 *dmsan_dir = alloc_printf("%s/dmsan_findings", afl->out_dir);
  if (mkdir((char *)dmsan_dir, 0700) && errno != EEXIST) {

    PFATAL("Unable to create '%s'", dmsan_dir);

  }
  ck_free(dmsan_dir);

  if (afl->san_binary_length) {

    u8 *msan_only_dir = alloc_printf("%s/msan_only", afl->out_dir);
    if (mkdir((char *)msan_only_dir, 0700) && errno != EEXIST) {
      PFATAL("Unable to create '%s'", msan_only_dir);
    }
    ck_free(msan_only_dir);

    u8 *dmsan_only_dir = alloc_printf("%s/dmsan_only", afl->out_dir);
    if (mkdir((char *)dmsan_only_dir, 0700) && errno != EEXIST) {
      PFATAL("Unable to create '%s'", dmsan_only_dir);
    }
    ck_free(dmsan_only_dir);

  }

  dmsan_recover_findings_state(afl);

  dmsan_setup_shm(afl);

  char shm_fast_str[32], shm_feedback_str[32], shm_full_str[32],
      shm_poison_str[32],
      shm_sitemap_str[32];
  snprintf(shm_fast_str, sizeof(shm_fast_str), "%d", afl->dmsan_shm_fast_id);
  snprintf(shm_poison_str, sizeof(shm_poison_str), "%d",
           afl->dmsan_shm_poison_id);
  setenv(DMSAN_FAST_SHM_ENV_VAR, shm_fast_str, 1);
  if (afl->dmsan_shm_feedback_id >= 0) {
    snprintf(shm_feedback_str, sizeof(shm_feedback_str), "%d",
             afl->dmsan_shm_feedback_id);
    setenv(DMSAN_FEEDBACK_SHM_ENV_VAR, shm_feedback_str, 1);
  } else {
    unsetenv(DMSAN_FEEDBACK_SHM_ENV_VAR);
  }
  if (afl->dmsan_shm_full_id >= 0) {
    snprintf(shm_full_str, sizeof(shm_full_str), "%d",
             afl->dmsan_shm_full_id);
    setenv(DMSAN_FULL_SHM_ENV_VAR, shm_full_str, 1);
  } else {
    unsetenv(DMSAN_FULL_SHM_ENV_VAR);
  }
  setenv(DMSAN_POISON_SHM_ENV_VAR, shm_poison_str, 1);
  if (afl->dmsan_shm_sitemap_id >= 0) {
    snprintf(shm_sitemap_str, sizeof(shm_sitemap_str), "%d",
             afl->dmsan_shm_sitemap_id);
    setenv(DMSAN_SITEMAP_SHM_ENV_VAR, shm_sitemap_str, 1);
  }

  dmsan_set_poison(afl, DMSAN_POISON_RUN1);
  dmsan_clear_map(afl);
  dmsan_set_fixed_values(afl);
  dmsan_ensure_trace_backup(afl, DEFAULT_SHMEM_SIZE);

  afl->dmsan_fsrv.map_size = DEFAULT_SHMEM_SIZE;
  afl->dmsan_fsrv.trace_bits = ck_alloc(DEFAULT_SHMEM_SIZE + 8);
  afl->dmsan_n_fuzz = ck_alloc(N_FUZZ_SIZE_BITMAP * sizeof(u8));
  afl->virgin_dmsan = ck_alloc(DEFAULT_SHMEM_SIZE);
  if (afl->san_binary_length) {
    afl->virgin_msan_only = ck_alloc(DEFAULT_SHMEM_SIZE);
    afl->virgin_dmsan_only = ck_alloc(DEFAULT_SHMEM_SIZE);
  }
  if (afl->dmsan_aux_compiled) {
    afl->virgin_dmsan_aux =
        ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
    memset(afl->virgin_dmsan_aux, 0xff,
           sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }
  if (afl->dmsan_clean_cache_enabled) {
    afl->dmsan_clean_cache_max = DMSAN_CLEAN_CACHE_DEFAULT_ENTRIES;
    afl->dmsan_clean_cache =
        ck_alloc(sizeof(struct dmsan_clean_cache_entry) *
                 afl->dmsan_clean_cache_max);
    afl->dmsan_clean_cache_next = 0;
  }
  afl->dmsan_probe_counts = ck_alloc_nozero(N_FUZZ_SIZE);
  dmsan_alloc_aux_cache(afl);
  afl->dmsan_enabled = 1;

  if (afl->debug) {
    DEBUGF("DMSAN integrated mode initialized (fast_id=%d, feedback_id=%d, poison_id=%d)\n",
           afl->dmsan_shm_fast_id, afl->dmsan_shm_feedback_id,
           afl->dmsan_shm_poison_id);
  }

}

/* ========== Child Execution ========== */

/* This function is called in the child process after fork(), before exec().
   It follows the same pattern as sanfuzz_exec_child() in afl-fuzz-sanfuzz.c.

   The DMSAN sidecar binary must be compiled with:
     AFL_DMSAN_MODE=fast afl-clang-fast -o target_dmsan target.c

   This ensures:
   - Forkserver support is included (afl-compiler-rt.o linked)
   - Coverage instrumentation is DISABLED (no trace_bits[hash]++)
   - DMSAN instrumentation is enabled (signature calculation)
*/
void dmsan_exec_child(afl_forkserver_t *fsrv, char **argv) {

  /* Replace argv[0] with DMSAN binary path */
  if (!fsrv->qemu_mode && !fsrv->frida_mode) {

    argv[0] = fsrv->target_path;

  }

  /* Execute the already-compiled DMSAN sidecar binary. */
  execv(fsrv->target_path, argv);

}

/* ========== Core Detection Logic ========== */

/* Debug helper: save detailed diff info when non-deterministic */
static void dmsan_save_nondet_debug(afl_state_t *afl, u8 *buf, u32 len) {

  u8 *fn = alloc_printf("%s/dmsan_findings/nondet_debug_%06llu.txt",
                        afl->out_dir,
                        (unsigned long long)afl->dmsan_nondets);

  FILE *f = fopen((char *)fn, "w");
  if (!f) {
    WARNF("Unable to create nondet debug '%s'", fn);
    ck_free(fn);
    return;
  }

  fprintf(f, "=== DMSAN Non-Deterministic Debug Info ===\n");
  fprintf(f, "Input len: %u\n\n", len);

  fprintf(f, "Run1 signatures:\n");
  fprintf(f, "  sum_signature:  0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot1->sum_signature);
  fprintf(f, "  rotl_signature: 0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot1->rotl_signature);
  fprintf(f, "  mul_signature:  0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot1->multiply_signature);
  fprintf(f, "  total_count:    %llu\n\n",
          (unsigned long long)afl->dmsan_snapshot1->total_count);

  fprintf(f, "Run2 signatures:\n");
  fprintf(f, "  sum_signature:  0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot2->sum_signature);
  fprintf(f, "  rotl_signature: 0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot2->rotl_signature);
  fprintf(f, "  mul_signature:  0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot2->multiply_signature);
  fprintf(f, "  total_count:    %llu\n\n",
          (unsigned long long)afl->dmsan_snapshot2->total_count);

  fprintf(f, "Differences:\n");
  if (afl->dmsan_snapshot1->sum_signature != afl->dmsan_snapshot2->sum_signature) {
    fprintf(f, "  sum_signature DIFFERS by: 0x%llx\n",
            (unsigned long long)(afl->dmsan_snapshot1->sum_signature ^
                                 afl->dmsan_snapshot2->sum_signature));
  }
  if (afl->dmsan_snapshot1->rotl_signature != afl->dmsan_snapshot2->rotl_signature) {
    fprintf(f, "  rotl_signature DIFFERS\n");
  }
  if (afl->dmsan_snapshot1->multiply_signature != afl->dmsan_snapshot2->multiply_signature) {
    fprintf(f, "  mul_signature DIFFERS\n");
  }
  if (afl->dmsan_snapshot1->total_count != afl->dmsan_snapshot2->total_count) {
    fprintf(f, "  total_count DIFFERS: Run1=%llu, Run2=%llu (diff=%lld)\n",
            (unsigned long long)afl->dmsan_snapshot1->total_count,
            (unsigned long long)afl->dmsan_snapshot2->total_count,
            (long long)(afl->dmsan_snapshot1->total_count -
                        afl->dmsan_snapshot2->total_count));
  }

  fprintf(f, "\nHint: Set DMSAN_TRACE_ALL=1 and re-run to see all checkpoints\n");

  fclose(f);

  /* Also save the input that caused non-determinism */
  u8 *input_fn = alloc_printf("%s/dmsan_findings/nondet_input_%06llu",
                              afl->out_dir,
                              (unsigned long long)afl->dmsan_nondets);
  s32 fd = open((char *)input_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd >= 0) {
    ck_write(fd, buf, len, input_fn);
    close(fd);
    u8 *sig_fn = alloc_printf("%s.sig", input_fn);
    dmsan_write_sig_sidecar(afl, (const char *)sig_fn,
                            DMSAN_NON_DETERMINISTIC, afl->dmsan_snapshot1,
                            afl->dmsan_snapshot2, afl->dmsan_snapshot3);
    ck_free(sig_fn);
  }
  ck_free(input_fn);

  WARNF("DMSAN non-deterministic debug saved to: %s", fn);
  ck_free(fn);

}

static void dmsan_save_timeout_debug(afl_state_t *afl, u8 *buf, u32 len,
                                     u8 run_id) {

  u8 *fn = alloc_printf("%s/dmsan_findings/timeout_debug_%06llu.txt",
                        afl->out_dir,
                        (unsigned long long)afl->dmsan_timeouts);

  FILE *f = fopen((char *)fn, "w");
  if (!f) {
    WARNF("Unable to create DMSAN timeout debug '%s'", fn);
    ck_free(fn);
    return;
  }

  fprintf(f, "=== DMSAN Timeout Debug Info ===\n");
  fprintf(f, "Input len: %u\n", len);
  fprintf(f, "Timed-out run: %u\n", (unsigned)run_id);
  fprintf(f, "Timeout ms: %u\n\n",
          afl->dmsan_inline_mode ? afl->fsrv.exec_tmout
                                 : afl->dmsan_fsrv.exec_tmout);

  fprintf(f, "Run1 count: %llu sum=0x%016llx rotl=0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot1->total_count,
          (unsigned long long)afl->dmsan_snapshot1->sum_signature,
          (unsigned long long)afl->dmsan_snapshot1->rotl_signature);
  fprintf(f, "Run2 count: %llu sum=0x%016llx rotl=0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot2->total_count,
          (unsigned long long)afl->dmsan_snapshot2->sum_signature,
          (unsigned long long)afl->dmsan_snapshot2->rotl_signature);
  fprintf(f, "Run3 count: %llu sum=0x%016llx rotl=0x%016llx\n",
          (unsigned long long)afl->dmsan_snapshot3->total_count,
          (unsigned long long)afl->dmsan_snapshot3->sum_signature,
          (unsigned long long)afl->dmsan_snapshot3->rotl_signature);

  fprintf(f, "\nThis is a DMSAN sidecar/confirmation timeout, not an AFL "
             "primary hang. Re-run with a larger -t to distinguish a true "
             "slow path from DMSAN overhead.\n");
  fclose(f);

  u8 *input_fn = alloc_printf("%s/dmsan_findings/timeout_input_%06llu",
                              afl->out_dir,
                              (unsigned long long)afl->dmsan_timeouts);
  s32 fd = open((char *)input_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd >= 0) {
    ck_write(fd, buf, len, input_fn);
    close(fd);
    u8 *sig_fn = alloc_printf("%s.sig", input_fn);
    dmsan_write_sig_sidecar(afl, (const char *)sig_fn, DMSAN_TIMEOUT,
                            afl->dmsan_snapshot1, afl->dmsan_snapshot2,
                            afl->dmsan_snapshot3);
    ck_free(sig_fn);
  }
  ck_free(input_fn);

  WARNF("DMSAN timeout debug saved to: %s", fn);
  ck_free(fn);

}

static inline dmsan_result_t dmsan_timeout_result(afl_state_t *afl, u8 *buf,
                                                  u32 len, u8 run_id) {

  ++afl->dmsan_timeouts;
  if (afl->dmsan_save_nondet && afl->dmsan_timeouts <= 20) {
    dmsan_save_timeout_debug(afl, buf, len, run_id);
  }
  return DMSAN_TIMEOUT;

}

dmsan_result_t dmsan_check(afl_state_t *afl, u8 *buf, u32 len) {

  dmsan_reset_current_finding(afl);
  afl->dmsan_total_checks++;
  afl->dmsan_direct_checks++;
  u64 input_hash = 0;
  u64 l2_key = 0;
  dmsan_run1_status_t run1 =
      dmsan_run1_prepare(afl, buf, len, &input_hash, &l2_key);

  if (run1 == DMSAN_RUN1_CLEAN_CACHE) { return DMSAN_CLEAN; }
  if (run1 == DMSAN_RUN1_TIMEOUT) {
    return dmsan_timeout_result(afl, buf, len, 1);
  }
  if (run1 == DMSAN_RUN1_CRASH || run1 == DMSAN_RUN1_ERROR) {

    afl->dmsan_crashes++;
    return DMSAN_CRASH;

  }

  if (afl->debug) {
    DEBUGF("DMSAN Run1: sum=0x%016llx rotl=0x%016llx cnt=%llu\n",
           (unsigned long long)afl->dmsan_snapshot1->sum_signature,
           (unsigned long long)afl->dmsan_snapshot1->rotl_signature,
           (unsigned long long)afl->dmsan_snapshot1->total_count);
  }

  return dmsan_complete_check_from_run1(afl, buf, len, input_hash, l2_key, 1);

}

/* Like dmsan_check() but used only for MSan cross-classification (to determine
   msan_only vs dmsan_only when MSan already triggered).  Counted separately so
   these supplemental runs do not inflate dmsan_direct_checks. */
dmsan_result_t dmsan_crosscheck(afl_state_t *afl, u8 *buf, u32 len) {

  dmsan_reset_current_finding(afl);
  afl->dmsan_total_checks++;
  afl->dmsan_crosscheck_checks++;
  u64 input_hash = 0;
  u64 l2_key = 0;
  dmsan_run1_status_t run1 =
      dmsan_run1_prepare(afl, buf, len, &input_hash, &l2_key);

  if (run1 == DMSAN_RUN1_CLEAN_CACHE) { return DMSAN_CLEAN; }
  if (run1 == DMSAN_RUN1_TIMEOUT) {
    return dmsan_timeout_result(afl, buf, len, 1);
  }
  if (run1 == DMSAN_RUN1_CRASH || run1 == DMSAN_RUN1_ERROR) {

    afl->dmsan_crashes++;
    return DMSAN_CRASH;

  }

  return dmsan_complete_check_from_run1(afl, buf, len, input_hash, l2_key, 0);

}

dmsan_result_t dmsan_integrated_check(afl_state_t *afl, u8 *buf, u32 len) {

  dmsan_reset_current_finding(afl);
  u64 input_hash = 0;
  u64 aux_cache_key = 0;
  afl->dmsan_total_checks++;
  afl->dmsan_integrated_checks++;
  afl->dmsan_last_aux_novelty = 0;
  afl->dmsan_last_aux_stable_sites = 0;
  afl->dmsan_last_aux_unstable_sites = 0;

  dmsan_save_snapshot(afl, afl->dmsan_snapshot1);
  dmsan_save_aux_snapshot(afl, afl->dmsan_aux_snapshot1);
  if (afl->dmsan_aux_feedback && afl->dmsan_aux_compiled) {
    afl->dmsan_last_aux_novelty = dmsan_aux_has_new_bits(afl);
    if (afl->dmsan_last_aux_novelty) { afl->dmsan_aux_feedback_hits++; }
  }
  if (afl->dmsan_aux_cache && afl->dmsan_aux_compiled) {
    aux_cache_key =
        dmsan_make_aux_cache_key(afl, afl->dmsan_aux_snapshot1);
  }

  if (dmsan_should_use_clean_cache(afl) && buf && len) {

    input_hash = dmsan_clean_cache_hash(buf, len);
    if (dmsan_clean_cache_lookup(afl, buf, len, input_hash)) {

      afl->dmsan_clean_cache_hits++;
      return DMSAN_CLEAN;

    }

  }

  if (afl->dmsan_aux_cache && afl->dmsan_aux_compiled &&
      dmsan_aux_cache_lookup_clean(afl, aux_cache_key)) {
    return DMSAN_CLEAN;
  }

  dmsan_ensure_trace_backup(afl, afl->fsrv.map_size);
  memcpy(afl->dmsan_trace_backup, afl->fsrv.trace_bits, afl->fsrv.map_size);
  afl->dmsan_checking = 1;

  /* Re-publish the input each Run. For non-shmem stdin/file targets the
     .cur_input file is already populated by the main exec, but under
     shmem-fuzz / persistent setups __afl_fuzz_ptr may have advanced past
     this input by the time we re-enter fuzz_run_target. write_to_testcase
     re-pins the buffer so Run2 / Run3 see the same bytes Run1 did. */
  fsrv_run_result_t ret = dmsan_inline_run_with_retries(
      afl, &buf, &len, DMSAN_POISON_RUN2, afl->dmsan_snapshot2,
      afl->dmsan_aux_snapshot2);

  if (ret == FSRV_RUN_CRASH || ret == FSRV_RUN_ERROR) {

    afl->dmsan_checking = 0;
    afl->dmsan_current_finding.crash_run = 2;
    afl->dmsan_current_finding.crash_signal = afl->fsrv.last_kill_signal;
    afl->dmsan_crashes++;
    return DMSAN_CRASH;

  }

  if (ret == FSRV_RUN_TMOUT) {
    afl->dmsan_checking = 0;
    return dmsan_timeout_result(afl, buf, len, 2);
  }

  if (dmsan_active_signatures_equal(afl, afl->dmsan_snapshot1,
                                    afl->dmsan_snapshot2)) {

    afl->dmsan_checking = 0;
    if (dmsan_should_use_clean_cache(afl) && buf && len) {
      dmsan_clean_cache_insert(afl, buf, len, input_hash);
    }
    if (afl->dmsan_aux_cache && afl->dmsan_aux_compiled) {
      dmsan_aux_cache_insert_clean(afl, aux_cache_key);
    }
    return DMSAN_CLEAN;

  }

  if (!afl->qdmsan_enabled && afl->dmsan_run3_dedup &&
      dmsan_precheck_run3(afl)) {
    afl->dmsan_checking = 0;
    ++afl->dmsan_deduped_runs;
    return DMSAN_DEDUPED;
  }

  ret = dmsan_inline_run_with_retries(
      afl, &buf, &len, DMSAN_POISON_RUN3, afl->dmsan_snapshot3,
      afl->dmsan_aux_snapshot3);
  afl->dmsan_checking = 0;

  if (ret == FSRV_RUN_CRASH || ret == FSRV_RUN_ERROR) {

    afl->dmsan_current_finding.crash_run = 3;
    afl->dmsan_current_finding.crash_signal = afl->fsrv.last_kill_signal;
    afl->dmsan_crashes++;
    return DMSAN_CRASH;

  }

  if (ret == FSRV_RUN_TMOUT) {
    return dmsan_timeout_result(afl, buf, len, 3);
  }

  return dmsan_finish_triplet(afl, buf, len);

}

/* Calibration reuse: calibrate_case captured Run1 in cycle 0 and Run2 in cycle
   1, including site_map snapshots when aux is compiled in. Compare the stashed
   pair and only spend a fresh Run3 when they diverge. */
dmsan_result_t dmsan_check_from_calibration(afl_state_t *afl, u8 *buf,
                                            u32 len) {

  dmsan_reset_current_finding(afl);
  if (!afl->dmsan_cal_have_sigs || !afl->dmsan_cal_sig1 ||
      !afl->dmsan_cal_sig2) {
    /* No stashed sigs - fall back to the regular integrated check. */
    return dmsan_integrated_check(afl, buf, len);
  }

  /* Mark consumed; the next calibration must repopulate. */
  afl->dmsan_cal_have_sigs = 0;

  afl->dmsan_total_checks++;
  afl->dmsan_integrated_checks++;
  afl->dmsan_last_aux_novelty = 0;
  afl->dmsan_last_aux_stable_sites = 0;
  afl->dmsan_last_aux_unstable_sites = 0;

  memcpy(afl->dmsan_snapshot1, afl->dmsan_cal_sig1,
         sizeof(struct dmsan_fast_map));
  memcpy(afl->dmsan_snapshot2, afl->dmsan_cal_sig2,
         sizeof(struct dmsan_fast_map));
  if (afl->dmsan_aux_compiled && afl->dmsan_cal_aux1 &&
      afl->dmsan_aux_snapshot1) {
    memcpy(afl->dmsan_aux_snapshot1, afl->dmsan_cal_aux1,
           sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
    if (afl->dmsan_aux_feedback) {
      afl->dmsan_last_aux_novelty =
          dmsan_aux_has_new_bits_for_map(afl, afl->dmsan_aux_snapshot1);
      if (afl->dmsan_last_aux_novelty) { afl->dmsan_aux_feedback_hits++; }
    }
  }
  if (afl->dmsan_aux_compiled && afl->dmsan_cal_aux2 &&
      afl->dmsan_aux_snapshot2) {
    memcpy(afl->dmsan_aux_snapshot2, afl->dmsan_cal_aux2,
           sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }

  if (dmsan_active_signatures_equal(afl, afl->dmsan_snapshot1,
                                    afl->dmsan_snapshot2)) {
    return DMSAN_CLEAN;
  }

  /* Sigs diverge -> run one fresh Run3 to distinguish a real UUM from nondet. */
  if (!afl->qdmsan_enabled && afl->dmsan_run3_dedup &&
      dmsan_precheck_run3(afl)) {
    ++afl->dmsan_deduped_runs;
    return DMSAN_DEDUPED;
  }

  dmsan_ensure_trace_backup(afl, afl->fsrv.map_size);
  memcpy(afl->dmsan_trace_backup, afl->fsrv.trace_bits, afl->fsrv.map_size);
  afl->dmsan_checking = 1;

  /* Re-publish the input - see the equivalent comment in
     dmsan_integrated_check; without this Run3 may consume a stale or
     truncated input under shmem-fuzz. */
  fsrv_run_result_t ret = dmsan_inline_run_with_retries(
      afl, &buf, &len, DMSAN_POISON_RUN3, afl->dmsan_snapshot3,
      afl->dmsan_aux_snapshot3);
  afl->dmsan_checking = 0;

  if (ret == FSRV_RUN_CRASH || ret == FSRV_RUN_ERROR) {
    afl->dmsan_current_finding.crash_run = 3;
    afl->dmsan_current_finding.crash_signal = afl->fsrv.last_kill_signal;
    afl->dmsan_crashes++;
    return DMSAN_CRASH;
  }

  if (ret == FSRV_RUN_TMOUT) {
    return dmsan_timeout_result(afl, buf, len, 3);
  }

  return dmsan_finish_triplet(afl, buf, len);

}

dmsan_result_t dmsan_maybe_probe_feedback(afl_state_t *afl, u8 *buf, u32 len,
                                          u64 trace_cksum, u8 *executed) {

  dmsan_reset_current_finding(afl);
  *executed = 0;
  if (!dmsan_should_probe_feedback(afl, trace_cksum)) { return DMSAN_CLEAN; }

  afl->dmsan_probe_runs++;
  u64 input_hash = 0;
  u64 aux_cache_key = 0;
  dmsan_run1_status_t run1 =
      dmsan_run1_prepare(afl, buf, len, &input_hash, &aux_cache_key);

  if (run1 == DMSAN_RUN1_CLEAN_CACHE) { return DMSAN_CLEAN; }
  if (run1 == DMSAN_RUN1_TIMEOUT) {
    *executed = 1;
    return dmsan_timeout_result(afl, buf, len, 1);
  }
  *executed = 1;

  if (run1 == DMSAN_RUN1_CRASH || run1 == DMSAN_RUN1_ERROR) {

    afl->dmsan_crashes++;
    return DMSAN_CRASH;

  }

  /* Probe escalates only when AUX_FEEDBACK is on AND the aux site_map
     showed novelty - the whole point of the old-path probe is to find
     buggy inputs whose simplified-trace was already dedup'd but whose
     aux signal is new. */
  if (!afl->dmsan_aux_feedback || !afl->dmsan_last_aux_novelty) {
    return DMSAN_CLEAN;
  }

  afl->dmsan_probe_promotions++;
  afl->dmsan_total_checks++;
  afl->dmsan_probe_checks++;
  return dmsan_complete_check_from_run1(afl, buf, len, input_hash,
                                        aux_cache_key, 1);

}

u8 dmsan_sample_run(afl_state_t *afl, u8 *buf, u32 len, u8 poison,
                    struct dmsan_fast_map *snapshot,
                    u16 *siteclass_snapshot) {

  if (!afl->dmsan_enabled) {
    dmsan_scrub_snapshot(snapshot, siteclass_snapshot);
    return FSRV_RUN_ERROR;
  }

  len = write_to_testcase(afl, (void **)&buf, len, 0);

  fsrv_run_result_t ret = FSRV_RUN_ERROR;

  for (int attempt = 0; attempt < 3; ++attempt) {

    dmsan_set_poison(afl, poison);
    dmsan_clear_map(afl);
    dmsan_set_fixed_values(afl);

    ret = afl_fsrv_run_target(&afl->dmsan_fsrv, afl->dmsan_fsrv.exec_tmout,
                              &afl->stop_soon);

    if (ret != FSRV_RUN_TMOUT) { break; }

  }

  if (!afl->dmsan_sitemap_count) { dmsan_read_sitemap(afl); }

  if (ret == FSRV_RUN_OK && snapshot) { dmsan_save_snapshot(afl, snapshot); }
  if (ret == FSRV_RUN_OK && siteclass_snapshot) {
    dmsan_save_aux_snapshot(afl, siteclass_snapshot);
  }
  if (ret != FSRV_RUN_OK) { dmsan_scrub_snapshot(snapshot, siteclass_snapshot); }

  return (u8)ret;

}

/* ========== Finding Storage ========== */

static void dmsan_write_sig_sidecar(afl_state_t *afl, const char *path,
                                    dmsan_result_t result,
                                    const struct dmsan_fast_map *s1,
                                    const struct dmsan_fast_map *s2,
                                    const struct dmsan_fast_map *s3) {

  FILE *f = fopen(path, "w");
  if (!f) { return; }
  fprintf(f, "result: %s\n", dmsan_result_name(result));
  if (afl->qdmsan_enabled) {
    fprintf(f, "candidate_planes: %s (0x%02x)\n",
            qdmsan_plane_mask_name(
                afl->dmsan_current_finding.candidate_mask),
            afl->dmsan_current_finding.candidate_mask);
    fprintf(f, "confirmed_planes: %s (0x%02x)\n",
            qdmsan_plane_mask_name(
                afl->dmsan_current_finding.confirmed_mask),
            afl->dmsan_current_finding.confirmed_mask);
    fprintf(f, "nondet_planes: %s (0x%02x)\n",
            qdmsan_plane_mask_name(afl->dmsan_current_finding.nondet_mask),
            afl->dmsan_current_finding.nondet_mask);
  }
  fprintf(f, "Run 1 (poison=0x%02x): sum=0x%016llx rotl=0x%016llx "
             "mul=0x%016llx count=%llu\n",
          DMSAN_POISON_RUN1, (unsigned long long)s1->sum_signature,
          (unsigned long long)s1->rotl_signature,
          (unsigned long long)s1->multiply_signature,
          (unsigned long long)s1->total_count);
  fprintf(f, "Run 2 (poison=0x%02x): sum=0x%016llx rotl=0x%016llx "
             "mul=0x%016llx count=%llu\n",
          DMSAN_POISON_RUN2, (unsigned long long)s2->sum_signature,
          (unsigned long long)s2->rotl_signature,
          (unsigned long long)s2->multiply_signature,
          (unsigned long long)s2->total_count);
  fprintf(f, "Run 3 (poison=0x%02x): sum=0x%016llx rotl=0x%016llx "
             "mul=0x%016llx count=%llu\n",
          DMSAN_POISON_RUN3, (unsigned long long)s3->sum_signature,
          (unsigned long long)s3->rotl_signature,
          (unsigned long long)s3->multiply_signature,
          (unsigned long long)s3->total_count);
  if (afl->qdmsan_enabled) {
    const struct dmsan_fast_map *runs[] = {s1, s2, s3};
    for (unsigned i = 0; i < 3; ++i) {
      fprintf(f,
              "Run %u QDMSan: OOB=(0x%016llx,0x%016llx,%llu) "
              "UAF=(0x%016llx,0x%016llx,%llu) abi=0x%016llx\n",
              i + 1,
              (unsigned long long)qdmsan_plane_sum(runs[i],
                                                    QDMSAN_PLANE_OOB),
              (unsigned long long)qdmsan_plane_rotl(runs[i],
                                                     QDMSAN_PLANE_OOB),
              (unsigned long long)qdmsan_plane_count(runs[i],
                                                      QDMSAN_PLANE_OOB),
              (unsigned long long)qdmsan_plane_sum(runs[i],
                                                    QDMSAN_PLANE_UAF),
              (unsigned long long)qdmsan_plane_rotl(runs[i],
                                                     QDMSAN_PLANE_UAF),
              (unsigned long long)qdmsan_plane_count(runs[i],
                                                      QDMSAN_PLANE_UAF),
              (unsigned long long)runs[i]->padding[QDMSAN_FAST_ABI_IDX]);
    }
  }
  /* Save the deterministic seed used by this fuzz session.  A replay tool
     can re-load these via env vars to reproduce the exact program execution
     environment (intercepted time/rand/tsc/rdrand). */
  fprintf(f, "fixed_time_sec=%llu\n",
          (unsigned long long)afl->dmsan_fixed_time_sec);
  fprintf(f, "fixed_time_usec=%llu\n",
          (unsigned long long)afl->dmsan_fixed_time_usec);
  fprintf(f, "fixed_rand_base=%llu\n",
          (unsigned long long)afl->dmsan_fixed_rand_base);
  fprintf(f, "fixed_tsc_base=%llu\n",
          (unsigned long long)afl->dmsan_fixed_tsc_base);
  fprintf(f, "fixed_rdrand_base=%llu\n",
          (unsigned long long)afl->dmsan_fixed_rdrand_base);
  fclose(f);

}

u8 dmsan_save_finding(afl_state_t *afl, u8 *buf, u32 len,
                      dmsan_result_t result, dmsan_finding_t *finding) {

  u8        *fn;
  s32        fd;

  /* Build finding record */
  finding->id = afl->dmsan_next_finding_id;
  finding->result = result;
  finding->timestamp = (u64)time(NULL);
  finding->crash_run = afl->dmsan_current_finding.crash_run;
  finding->crash_signal = afl->dmsan_current_finding.crash_signal;
  finding->candidate_mask = afl->dmsan_current_finding.candidate_mask;
  finding->confirmed_mask = afl->dmsan_current_finding.confirmed_mask;
  finding->nondet_mask = afl->dmsan_current_finding.nondet_mask;

  /* Copy signatures */
  finding->sig1_sum = afl->dmsan_snapshot1->sum_signature;
  finding->sig1_rotl = afl->dmsan_snapshot1->rotl_signature;
  finding->sig1_mul = afl->dmsan_snapshot1->multiply_signature;
  finding->sig1_count = afl->dmsan_snapshot1->total_count;

  finding->sig2_sum = afl->dmsan_snapshot2->sum_signature;
  finding->sig2_rotl = afl->dmsan_snapshot2->rotl_signature;
  finding->sig2_mul = afl->dmsan_snapshot2->multiply_signature;
  finding->sig2_count = afl->dmsan_snapshot2->total_count;

  finding->sig3_sum = afl->dmsan_snapshot3->sum_signature;
  finding->sig3_rotl = afl->dmsan_snapshot3->rotl_signature;
  finding->sig3_mul = afl->dmsan_snapshot3->multiply_signature;
  finding->sig3_count = afl->dmsan_snapshot3->total_count;

  /* Build filename - use describe_op for consistent naming with crashes/.
     QDMSan persists its confirmed class even when debug .sig sidecars are
     disabled. */
  if (afl->qdmsan_enabled) {
    fn = alloc_printf(
        "%s/dmsan_findings/id:%06llu,result:%s,planes:%s,%s", afl->out_dir,
        finding->id, dmsan_result_name(result),
        qdmsan_plane_mask_name(finding->confirmed_mask),
        describe_op(afl, 0,
                    NAME_MAX -
                        strlen("id:000000,result:bug,planes:UUM|OOB|UAF,")));
  } else {
    fn = alloc_printf(
        "%s/dmsan_findings/id:%06llu,result:%s,%s", afl->out_dir,
        finding->id, dmsan_result_name(result),
        describe_op(afl, 0, NAME_MAX - strlen("id:000000,result:bug,")));
  }

  /* Save the input */
  fd = open((char *)fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {

    if (errno != EEXIST) { WARNF("Unable to create '%s'", fn); }
    ck_free(fn);
    return 0;

  }

  ck_write(fd, buf, len, fn);
  close(fd);

  if (dmsan_should_write_sig_sidecar(afl)) {
    u8 *sig_path = alloc_printf("%s.sig", fn);
    dmsan_write_sig_sidecar(afl, (const char *)sig_path, result,
                            afl->dmsan_snapshot1, afl->dmsan_snapshot2,
                            afl->dmsan_snapshot3);
    ck_free(sig_path);
  }

  if (afl->debug) { DEBUGF("DMSAN finding saved: %s\n", fn); }
  ck_free(fn);
  ++afl->saved_dmsan_findings;
  ++afl->dmsan_next_finding_id;
  dmsan_persist_dedup_state(afl);

  /* Update JSON report */
  dmsan_update_report(afl);
  return 1;

}

void dmsan_replay_single_file(afl_state_t *afl, const char *path) {

  s32 fd = open(path, O_RDONLY);
  if (fd < 0) {
    FATAL("DMSAN replay: cannot open '%s': %s", path, strerror(errno));
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size <= 0) {
    close(fd);
    FATAL("DMSAN replay: empty or unreadable '%s'", path);
  }

  u32 len = (u32)st.st_size;
  u8 *buf = ck_alloc_nozero(len);
  if (read(fd, buf, len) != (ssize_t)len) {
    close(fd);
    ck_free(buf);
    FATAL("DMSAN replay: short read on '%s'", path);
  }
  close(fd);

  dmsan_result_t result = dmsan_check(afl, buf, len);

  u8 *sig_path = alloc_printf("%s.sig", path);
  dmsan_write_sig_sidecar(afl, (const char *)sig_path, result,
                          afl->dmsan_snapshot1, afl->dmsan_snapshot2,
                          afl->dmsan_snapshot3);
  SAYF(cLGN "[+] DMSAN replay done: %s\n" cRST, sig_path);
  SAYF("    result=%s\n", dmsan_result_name(result));
  if (afl->qdmsan_enabled) {
    SAYF("    planes: candidate=%s confirmed=%s nondet=%s\n",
         qdmsan_plane_mask_name(afl->dmsan_current_finding.candidate_mask),
         qdmsan_plane_mask_name(afl->dmsan_current_finding.confirmed_mask),
         qdmsan_plane_mask_name(afl->dmsan_current_finding.nondet_mask));
  }
  SAYF("    Run1 sum=0x%016llx rotl=0x%016llx count=%llu\n",
       (unsigned long long)afl->dmsan_snapshot1->sum_signature,
       (unsigned long long)afl->dmsan_snapshot1->rotl_signature,
       (unsigned long long)afl->dmsan_snapshot1->total_count);
  SAYF("    Run2 sum=0x%016llx rotl=0x%016llx count=%llu\n",
       (unsigned long long)afl->dmsan_snapshot2->sum_signature,
       (unsigned long long)afl->dmsan_snapshot2->rotl_signature,
       (unsigned long long)afl->dmsan_snapshot2->total_count);
  SAYF("    Run3 sum=0x%016llx rotl=0x%016llx count=%llu\n",
       (unsigned long long)afl->dmsan_snapshot3->sum_signature,
       (unsigned long long)afl->dmsan_snapshot3->rotl_signature,
       (unsigned long long)afl->dmsan_snapshot3->total_count);

  ck_free(sig_path);
  ck_free(buf);
  exit(0);

}

u8 dmsan_save_categorized_finding(afl_state_t *afl, u8 *buf, u32 len,
                                  const char *subdir, u64 *next_id,
                                  u64 *saved_count) {

  u8  *fn;
  s32  fd;
  u64  id = *next_id;

  fn = alloc_printf("%s/%s/id:%06llu,%s", afl->out_dir, subdir, id,
                    describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

  fd = open((char *)fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {

    if (errno != EEXIST) { WARNF("Unable to create '%s'", fn); }
    ck_free(fn);
    return 0;

  }

  ck_write(fd, buf, len, fn);
  close(fd);

  if (afl->debug) { DEBUGF("DMSAN categorized finding saved: %s\n", fn); }

  ck_free(fn);
  ++(*saved_count);
  ++(*next_id);
  dmsan_persist_dedup_state(afl);
  dmsan_update_report(afl);
  return 1;

}

/* ========== JSON Report ========== */

void dmsan_update_report(afl_state_t *afl) {

  u8   *fn = alloc_printf("%s/dmsan_findings/report.json", afl->out_dir);
  FILE *f = fopen((char *)fn, "w");

  if (!f) {

    WARNF("Unable to create DMSAN report '%s'", fn);
    ck_free(fn);
    return;

  }

  fprintf(f, "{\n");
  fprintf(f, "  \"version\": \"1.0\",\n");
  fprintf(f, "  \"start_time\": %llu,\n", (unsigned long long)afl->start_time / 1000);
  fprintf(f, "  \"last_update\": %llu,\n", (unsigned long long)time(NULL));
  fprintf(f, "  \"stats\": {\n");
  fprintf(f, "    \"total_checks\": %llu,\n",
          (unsigned long long)afl->dmsan_total_checks);
  fprintf(f, "    \"bugs_found\": %llu,\n",
          (unsigned long long)afl->dmsan_bugs_found);
  fprintf(f, "    \"crashes\": %llu,\n", (unsigned long long)afl->dmsan_crashes);
  fprintf(f, "    \"last_crash_run\": %d,\n",
          afl->dmsan_current_finding.crash_run);
  fprintf(f, "    \"last_crash_signal\": %d,\n",
          afl->dmsan_current_finding.crash_signal);
  fprintf(f, "    \"last_candidate_mask\": %u,\n",
          (unsigned)afl->dmsan_current_finding.candidate_mask);
  fprintf(f, "    \"last_confirmed_mask\": %u,\n",
          (unsigned)afl->dmsan_current_finding.confirmed_mask);
  fprintf(f, "    \"last_nondet_mask\": %u,\n",
          (unsigned)afl->dmsan_current_finding.nondet_mask);
  fprintf(f, "    \"non_deterministic\": %llu,\n",
          (unsigned long long)afl->dmsan_nondets);
  fprintf(f, "    \"timeouts\": %llu,\n",
          (unsigned long long)afl->dmsan_timeouts);
  fprintf(f, "    \"saved_findings\": %llu,\n",
          (unsigned long long)afl->saved_dmsan_findings);
  fprintf(f, "    \"saved_msan_only\": %llu,\n",
          (unsigned long long)afl->saved_msan_only);
  fprintf(f, "    \"saved_dmsan_only\": %llu,\n",
          (unsigned long long)afl->saved_dmsan_only);
  fprintf(f, "    \"aux_novelty\": %llu,\n",
          (unsigned long long)afl->dmsan_aux_feedback_hits);
  fprintf(f, "    \"aux_rescues\": %llu,\n",
          (unsigned long long)afl->dmsan_aux_rescues);
  fprintf(f, "    \"nondet_site_inputs\": %llu,\n",
          (unsigned long long)afl->dmsan_nondet_site_inputs);
  fprintf(f, "    \"nondet_site_polluted\": %llu,\n",
          (unsigned long long)afl->dmsan_nondet_site_polluted);
  fprintf(f, "    \"aux_cache_hits\": %llu,\n",
          (unsigned long long)afl->dmsan_aux_cache_hits);
  fprintf(f, "    \"aux_cache_total\": %llu,\n",
          (unsigned long long)(afl->dmsan_aux_cache_hits +
                               afl->dmsan_aux_cache_misses));
  fprintf(f, "    \"clean_cache_hits\": %llu,\n",
          (unsigned long long)afl->dmsan_clean_cache_hits);
  fprintf(f, "    \"clean_cache_inserts\": %llu,\n",
          (unsigned long long)afl->dmsan_clean_cache_inserts);
  fprintf(f, "    \"probe_runs\": %llu,\n",
          (unsigned long long)afl->dmsan_probe_runs);
  fprintf(f, "    \"probe_promotions\": %llu,\n",
          (unsigned long long)afl->dmsan_probe_promotions);
  fprintf(f, "    \"direct_checks\": %llu,\n",
          (unsigned long long)afl->dmsan_direct_checks);
  fprintf(f, "    \"probe_checks\": %llu,\n",
          (unsigned long long)afl->dmsan_probe_checks);
  fprintf(f, "    \"integrated_checks\": %llu,\n",
          (unsigned long long)afl->dmsan_integrated_checks);
  fprintf(f, "    \"crosscheck_checks\": %llu,\n",
          (unsigned long long)afl->dmsan_crosscheck_checks);
  fprintf(f, "    \"deploy\": \"%s\",\n",
          afl->dmsan_inline_mode ? "inline" : "sidecar");
  fprintf(f, "    \"aux_compiled\": %u,\n",
          (unsigned)afl->dmsan_aux_compiled);
  fprintf(f, "    \"aux_feedback\": %u,\n",
          (unsigned)afl->dmsan_aux_feedback);
  fprintf(f, "    \"aux_cache\": %u,\n", (unsigned)afl->dmsan_aux_cache);
  fprintf(f, "    \"aux_nondet\": %u\n", (unsigned)afl->dmsan_aux_nondet);
  fprintf(f, "  }\n");
  fprintf(f, "}\n");

  fclose(f);
  ck_free(fn);

}

/* ========== Cleanup ========== */

void dmsan_deinit(afl_state_t *afl) {

  if (!afl->dmsan_enabled) { return; }

  /* Cleanup shared memory */
  if (afl->dmsan_shm_fast && afl->dmsan_shm_fast != (void *)-1) {

    shmdt(afl->dmsan_shm_fast);

  }

  if (afl->dmsan_shm_feedback && afl->dmsan_shm_feedback != (void *)-1) {

    shmdt(afl->dmsan_shm_feedback);

  }

  if (afl->dmsan_shm_full && afl->dmsan_shm_full != (void *)-1) {

    shmdt(afl->dmsan_shm_full);

  }

  if (afl->dmsan_shm_poison && afl->dmsan_shm_poison != (void *)-1) {

    shmdt(afl->dmsan_shm_poison);

  }

  if (afl->dmsan_shm_sitemap_ptr && afl->dmsan_shm_sitemap_ptr != (void *)-1) {

    shmdt(afl->dmsan_shm_sitemap_ptr);

  }

  /* Free snapshots */
  if (afl->dmsan_snapshot1) { ck_free(afl->dmsan_snapshot1); }
  if (afl->dmsan_snapshot2) { ck_free(afl->dmsan_snapshot2); }
  if (afl->dmsan_snapshot3) { ck_free(afl->dmsan_snapshot3); }
  if (afl->dmsan_aux_snapshot1) { ck_free(afl->dmsan_aux_snapshot1); }
  if (afl->dmsan_aux_snapshot2) { ck_free(afl->dmsan_aux_snapshot2); }
  if (afl->dmsan_aux_snapshot3) { ck_free(afl->dmsan_aux_snapshot3); }
  if (afl->dmsan_cal_sig1) { ck_free(afl->dmsan_cal_sig1); }
  if (afl->dmsan_cal_sig2) { ck_free(afl->dmsan_cal_sig2); }
  if (afl->dmsan_cal_aux1) { ck_free(afl->dmsan_cal_aux1); }
  if (afl->dmsan_cal_aux2) { ck_free(afl->dmsan_cal_aux2); }
  if (afl->dmsan_trace_backup) { ck_free(afl->dmsan_trace_backup); }
  if (afl->dmsan_trace_scratch) { ck_free(afl->dmsan_trace_scratch); }
  if (afl->dmsan_sitemap) { ck_free(afl->dmsan_sitemap); }

  /* Free trace_bits allocated for DMSAN forkserver */
  if (afl->dmsan_fsrv.trace_bits) { ck_free(afl->dmsan_fsrv.trace_bits); }

  /* Free simplified trace dedup bitmap */
  if (afl->dmsan_n_fuzz) { ck_free(afl->dmsan_n_fuzz); }

  /* Free virgin_dmsan bitmap */
  if (afl->virgin_dmsan) { ck_free(afl->virgin_dmsan); }
  if (afl->virgin_msan_only) { ck_free(afl->virgin_msan_only); }
  if (afl->virgin_dmsan_only) { ck_free(afl->virgin_dmsan_only); }
  if (afl->virgin_dmsan_aux) { ck_free(afl->virgin_dmsan_aux); }
  if (afl->dmsan_probe_counts) { ck_free(afl->dmsan_probe_counts); }
  if (afl->dmsan_aux_cache_table) { ck_free(afl->dmsan_aux_cache_table); }
  if (afl->dmsan_clean_cache) {

    for (u32 i = 0; i < afl->dmsan_clean_cache_max; ++i) {

      if (afl->dmsan_clean_cache[i].buf) {
        ck_free(afl->dmsan_clean_cache[i].buf);
      }

    }

    ck_free(afl->dmsan_clean_cache);

  }

  /* Kill DMSAN forkserver */
  afl_fsrv_kill(&afl->dmsan_fsrv);

  if (afl->debug) { DEBUGF("DMSAN cleaned up\n"); }

}
