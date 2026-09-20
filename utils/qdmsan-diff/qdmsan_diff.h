/*
   qdmsan-diff - standalone QDMSAN replay helper
   ------------------------------------------------

   The tool mirrors the AFL++/DMSAN three-run protocol for clean QEMU targets:

     Run1: selector 0x11, baseline
     Run2: selector 0x22, differential detection
     Run3: selector 0x11, nondeterminism check

   QDMSAN uses QEMU-side dangerous-use checkpoints and libqdmsan heap/libc
   hooks. The target binary itself is not compiled with DMSAN/QDMSAN.
 */

#ifndef QDMSAN_DIFF_H
#define QDMSAN_DIFF_H

#include "dmsanfuzz.h"
#include "forkserver.h"
#include "sharedmem.h"
#include "types.h"

#include <stdint.h>
#include <stdio.h>

typedef enum {

  QDMSAN_DIFF_MODE_FAST = 0,
  QDMSAN_DIFF_MODE_FAST_AUX,
  QDMSAN_DIFF_MODE_FULL,

} qdmsan_diff_mode_t;

typedef enum {

  QDMSAN_DIFF_CHECK_RAW = 0,
  QDMSAN_DIFF_CHECK_RESULT,

} qdmsan_diff_check_t;

typedef enum {

  QDMSAN_DIFF_CLEAN = 0,
  QDMSAN_DIFF_BUG = 1,
  QDMSAN_DIFF_NONDET = 2,
  QDMSAN_DIFF_CRASH = 3,
  QDMSAN_DIFF_TIMEOUT = 4,
  QDMSAN_DIFF_ERROR = 5,

} qdmsan_diff_result_t;

typedef struct qdmsan_diff_ctx {

  char **target_argv;
  int    target_argc;
  char  *target_path;
  char  *qemu_path;
  char  *libqdmsan_path;
  char **exec_argv;

  qdmsan_diff_mode_t  mode;
  qdmsan_diff_check_t check;
  u32                 timeout_ms;
  u32                 confirm_runs;
  u32                 report_limit;
  u8                  verbose;
  u8                  quiet;
  u8                  last_verdict_aux_rescue;
  u8                  candidate_mask;
  u8                  confirmed_mask;
  u8                  nondet_mask;
  volatile u8         stop_soon;

  afl_forkserver_t fsrv;
  sharedmem_t      afl_shm;
  u8              *trace_bits;
  u8               fsrv_started;

  int            input_fd;
  char           input_path[512];
  u8            *input_buf;
  size_t         input_len;
  u8             input_is_file_arg;
  char         **owned_target_argv;

  int shm_fast_id;
  int shm_feedback_id;
  int shm_full_id;
  int shm_poison_id;

  struct dmsan_fast_map    *fast_map;
  struct dmsan_feedback_shm *feedback_map;
  struct dmsan_full_shm    *full_map;
  u8                       *poison_byte;
  u64                       full_entries;

  struct dmsan_fast_map snap1;
  struct dmsan_fast_map snap2;
  struct dmsan_fast_map snap3;

  /* Coarse state oracle. Same poisoning and same three runs, but the verdict
     compares AFL edge hit-count buckets instead of checkpoint digests. */
  u8 state_oracle;
  u8 *cov1;
  u8 *cov2;
  u8 *cov3;

  u16 *aux1;
  u16 *aux2;
  u16 *aux3;

  struct dmsan_full_meta  full_meta1;
  struct dmsan_full_meta  full_meta2;
  struct dmsan_full_meta  full_meta3;
  struct dmsan_full_entry *full_entries1;
  struct dmsan_full_entry *full_entries2;
  struct dmsan_full_entry *full_entries3;

  u64 fixed_time_sec;
  u64 fixed_time_usec;
  u64 fixed_rand_base;
  u64 fixed_tsc_base;
  u64 fixed_rdrand_base;

  u64 total_runs;
  u64 full_compared_slots;
  u64 full_nondet_slots;
  u64 full_diff_slots;
  u64 first_diff_slot;

} qdmsan_diff_ctx_t;

const char *qdmsan_diff_result_name(qdmsan_diff_result_t result);
const char *qdmsan_diff_mode_name(qdmsan_diff_mode_t mode);
const char *qdmsan_diff_check_name(qdmsan_diff_check_t check);

int qdmsan_diff_init(qdmsan_diff_ctx_t *ctx);
qdmsan_diff_result_t qdmsan_diff_check(qdmsan_diff_ctx_t *ctx);
void qdmsan_diff_report(qdmsan_diff_ctx_t *ctx, qdmsan_diff_result_t result);
void qdmsan_diff_cleanup(qdmsan_diff_ctx_t *ctx);

#endif
