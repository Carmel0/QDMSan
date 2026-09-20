/* Test driver for the production calibration and per-execution hook.
 * Only child execution, testcase I/O and UI/scoring are simulated. Coverage
 * classification, novelty tracking, hashing, and calibration run unchanged. */
#include "afl-fuzz.h"
#include "afl-ijon-min.h"
#include "cmplog.h"
#include "dmsanfuzz.h"
#include <assert.h>

static afl_state_t *current;
static unsigned executions, run1_count;
static int true_nondeterminism, fail_run2;

fsrv_run_result_t afl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout,
                                     volatile u8 *stop) {
  (void)timeout; (void)stop;
  ++executions;
  u8 poison = *current->dmsan_shm_poison;
  memset(fsrv->trace_bits, 0, fsrv->map_size);
  if (poison == DMSAN_POISON_RUN2) {
    fsrv->trace_bits[2] = 1;
    if (fail_run2) return FSRV_RUN_TMOUT;
  } else {
    ++run1_count;
    fsrv->trace_bits[1] = 1;
    if (true_nondeterminism && run1_count > 1) fsrv->trace_bits[3] = 1;
  }
  struct dmsan_fast_map *sig = (void *)current->dmsan_shm_fast;
  sig->sum_signature = poison;
  sig->rotl_signature = poison;
  sig->total_count = 1;
  return FSRV_RUN_OK;
}

u32 write_to_testcase(afl_state_t *afl, void **buf, u32 len, u32 fix) {
  (void)afl; (void)buf; (void)fix; return len;
}
void afl_fsrv_start(afl_forkserver_t *f, char **a, volatile u8 *s, u8 d) {
  (void)f; (void)a; (void)s; (void)d; abort();
}
void afl_shm_deinit(sharedmem_t *s) { (void)s; abort(); }
void cmplog_exec_child(afl_forkserver_t *f, char **a) { (void)f; (void)a; abort(); }
void show_stats(afl_state_t *a) { (void)a; }
void update_calibration_time(afl_state_t *a, u64 *t) { (void)a; (void)t; }
void update_bitmap_score(afl_state_t *a, struct queue_entry *q, bool b) {
  (void)a; (void)q; (void)b;
}
void ijon_update_max_dynamic(ijon_min_state *s, dynamic_shared_access_t *a,
                             uint8_t *d, size_t n) {
  (void)s; (void)a; (void)d; (void)n; abort();
}

static void scenario(const char *name, int qdmsan, int compat, int nondet,
                     int reuse, int fast, int failing) {
  afl_state_t *a = calloc(1, sizeof(*a));
  struct queue_entry q = {0};
  struct dmsan_fast_map map = {0}, sig1 = {0}, sig2 = {0};
  u8 poison = DMSAN_POISON_RUN1, input = 0;
  current = a;
  executions = run1_count = 0;
  true_nondeterminism = nondet;
  fail_run2 = failing;
  if (compat) setenv("AFL_QDMSAN_PAPER_COMPAT", "1", 1);
  else unsetenv("AFL_QDMSAN_PAPER_COMPAT");
  a->dmsan_enabled = a->dmsan_inline_mode = 1;
  a->qdmsan_enabled = qdmsan;
  a->dmsan_cal_reuse_enabled = reuse;
  a->dmsan_shm_fast = (u8 *)&map;
  a->dmsan_shm_poison = &poison;
  a->dmsan_cal_sig1 = &sig1;
  a->dmsan_cal_sig2 = &sig2;
  a->fsrv.fsrv_pid = 1; /* Already started; no real child in this fixture. */
  a->fsrv.exec_tmout = 1000;
  a->fsrv.map_size = a->fsrv.real_map_size = 64;
  a->fsrv.trace_bits = calloc(64, 1);
  a->first_trace = calloc(64, 1);
  a->var_bytes = calloc(64, 1);
  a->virgin_bits = malloc(64);
  memset(a->virgin_bits, 255, 64);
  a->afl_env.afl_cal_fast = fast;
  a->afl_env.afl_no_warn_instability = 1;
  a->fixed_seed = 1;
  q.fname = (u8 *)"synthetic";
  q.len = 1;
  u8 fault = calibrate_case(a, &q, &input, 0, 1);
  if (failing) {
    assert(fault == FSRV_RUN_TMOUT && executions == 2);
    assert(!a->dmsan_cal_have_sigs && !a->dmsan_checking);
    assert(poison == DMSAN_POISON_RUN1);
  } else {
    assert(fault == FSRV_RUN_OK);
    int isolate = qdmsan && !compat;
    int expect_variable = nondet || (reuse && !isolate);
    assert(q.var_behavior == expect_variable);
    assert(a->var_bytes[2] == (reuse && !isolate));
    assert(a->virgin_bits[2] == (reuse && !isolate ? 0 : 255));
    assert(a->var_bytes[3] == nondet);
    unsigned expected = expect_variable ? (fast ? CAL_CYCLES : CAL_CYCLES_LONG)
                                       : (fast ? CAL_CYCLES_FAST : CAL_CYCLES);
    assert(executions == expected && a->total_cal_cycles == expected);
    assert(a->total_cal_us == (u64)(a->fsrv.exec_tmout - 1) * expected);
    assert(a->dmsan_cal_have_sigs == reuse);
    if (reuse) {
      assert(sig1.sum_signature == DMSAN_POISON_RUN1);
      assert(sig2.sum_signature == DMSAN_POISON_RUN2);
    }
    assert(a->fsrv.trace_bits[2] == 0);
  }
  printf("PASS %s runs=%u variable=%u r2_virgin=%u signatures=%u\n", name,
         executions, q.var_behavior, a->virgin_bits[2], a->dmsan_cal_have_sigs);
  free(a->dmsan_trace_backup);
  free(a->fsrv.trace_bits); free(a->first_trace); free(a->var_bytes);
  free(a->virgin_bits); free(a);
}

int main(void) {
  init_count_class16();
  scenario("QDMSan controlled fill", 1, 0, 0, 1, 1, 0);
  scenario("QDMSan slow calibration", 1, 0, 0, 1, 0, 0);
  scenario("QDMSan true same-fill variation", 1, 0, 1, 1, 1, 0);
  scenario("QDMSan reuse disabled", 1, 0, 0, 0, 1, 0);
  scenario("QDMSan reuse disabled variation", 1, 0, 1, 0, 1, 0);
  scenario("paper compatibility", 1, 1, 0, 1, 1, 0);
  scenario("compiler DMSan unchanged", 0, 0, 0, 1, 1, 0);
  scenario("compiler DMSan with compatibility env", 0, 1, 0, 1, 1, 0);
  scenario("R2 timeout resets state", 1, 0, 0, 1, 1, 1);
  return 0;
}
