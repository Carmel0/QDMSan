/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "exec/tb-lookup.h"
#include "disas/disas.h"
#include "exec/log.h"
#include "tcg/tcg.h"
#include "qemu/processor.h"

#include "qemuafl/common.h"
#include "qemuafl/qemu-ijon-support.h"

uint32_t afl_hash_ip(uint64_t);

void HELPER(ijon_func_call)(target_ulong var_addr, target_ulong var_len, target_ulong itype, target_ulong idx)
{
  uint64_t buf = 0;
  memcpy(&buf, (const void *)var_addr, var_len);
  ijon_dispatch(itype, idx, buf);
  fprintf(stderr, "trigger ijon: addr=0x%016" PRIx64 " tag=%s value %ld\n", var_addr, ijon_to_str(itype), buf);
}

void HELPER(afl_entry_routine)(CPUArchState *env) {

  afl_forkserver(env_cpu(env));

}

void HELPER(afl_persistent_routine)(CPUArchState *env) {

  afl_persistent_loop(env);

}

void HELPER(afl_compcov_16)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {

  register uintptr_t idx = cur_loc;

  if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(idx); }

}

void HELPER(afl_compcov_32)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {

  register uintptr_t idx = cur_loc;

  if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

    INC_AFL_AREA(idx + 2);
    if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

      INC_AFL_AREA(idx + 1);
      if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(idx); }

    }

  }

}

void HELPER(afl_compcov_64)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {

  register uintptr_t idx = cur_loc;

  if ((arg1 & 0xff00000000000000) == (arg2 & 0xff00000000000000)) {

    INC_AFL_AREA(idx + 6);
    if ((arg1 & 0xff000000000000) == (arg2 & 0xff000000000000)) {

      INC_AFL_AREA(idx + 5);
      if ((arg1 & 0xff0000000000) == (arg2 & 0xff0000000000)) {

        INC_AFL_AREA(idx + 4);
        if ((arg1 & 0xff00000000) == (arg2 & 0xff00000000)) {

          INC_AFL_AREA(idx + 3);
          if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

            INC_AFL_AREA(idx + 2);
            if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

              INC_AFL_AREA(idx + 1);
              if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(idx); }

            }

          }

        }

      }

    }

  }

}

void HELPER(afl_cmplog_8)(target_ulong cur_loc, target_ulong arg1,
                          target_ulong arg2) {

  register uintptr_t k = (uintptr_t)cur_loc;
  u32 hits = 0;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS)
    __afl_cmp_map->headers[k].hits = 0;

  if (__afl_cmp_map->headers[k].hits == 0) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    __afl_cmp_map->headers[k].shape = 0;

  } else {

    hits = __afl_cmp_map->headers[k].hits;

  }

  __afl_cmp_map->headers[k].hits = hits + 1;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void HELPER(afl_cmplog_16)(target_ulong cur_loc, target_ulong arg1,
                           target_ulong arg2) {

  register uintptr_t k = (uintptr_t)cur_loc;
  u32 hits = 0;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS)
    __afl_cmp_map->headers[k].hits = 0;

  if (__afl_cmp_map->headers[k].hits == 0) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    __afl_cmp_map->headers[k].shape = 1;

  } else {

    hits = __afl_cmp_map->headers[k].hits;

  }

  __afl_cmp_map->headers[k].hits = hits + 1;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void HELPER(afl_cmplog_32)(target_ulong cur_loc, target_ulong arg1,
                           target_ulong arg2) {

  register uintptr_t k = (uintptr_t)cur_loc;
  u32 hits = 0;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS)
    __afl_cmp_map->headers[k].hits = 0;

  if (__afl_cmp_map->headers[k].hits == 0) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    __afl_cmp_map->headers[k].shape = 3;

  } else {

    hits = __afl_cmp_map->headers[k].hits;

  }

  __afl_cmp_map->headers[k].hits = hits + 1;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void HELPER(afl_cmplog_64)(target_ulong cur_loc, target_ulong arg1,
                           target_ulong arg2) {

  register uintptr_t k = (uintptr_t)cur_loc;
  u32 hits = 0;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS)
    __afl_cmp_map->headers[k].hits = 0;

  if (__afl_cmp_map->headers[k].hits == 0) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    __afl_cmp_map->headers[k].shape = 7;

  } else {

    hits = __afl_cmp_map->headers[k].hits;

  }

  __afl_cmp_map->headers[k].hits = hits + 1;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

#include <sys/mman.h>
#include "linux-user/qemu.h" /* access_ok decls. */

/*
static int area_is_mapped(void *ptr, size_t len) {

  char *p = ptr;
  char *page = (char *)((uintptr_t)p & ~(sysconf(_SC_PAGE_SIZE) - 1));

  int r = msync(page, (p - page) + len, MS_ASYNC);
  if (r < 0) return errno != ENOMEM;
  return 1;

}
*/

void HELPER(afl_cmplog_rtn)(CPUArchState *env) {

#if defined(TARGET_X86_64)

  target_ulong arg1 = env->regs[R_EDI];
  target_ulong arg2 = env->regs[R_ESI];

#elif defined(TARGET_I386)

  target_ulong *stack = AFL_G2H(env->regs[R_ESP]);
  
  if (!access_ok(env_cpu(env), VERIFY_READ, env->regs[R_ESP],
                 sizeof(target_ulong) * 2))
    return;

  // when this hook is executed, the retaddr is not on stack yet
  target_ulong arg1 = stack[0];
  target_ulong arg2 = stack[1];

#else

  // stupid code to make it compile
  target_ulong arg1 = 0;
  target_ulong arg2 = 0;
  return;

#endif

  if (!access_ok(env_cpu(env), VERIFY_READ, arg1, 0x20) ||
      !access_ok(env_cpu(env), VERIFY_READ, arg2, 0x20))
    return;

  void *ptr1 = AFL_G2H(arg1);
  void *ptr2 = AFL_G2H(arg2);

#if defined(TARGET_X86_64) || defined(TARGET_I386)
  uintptr_t k = (uintptr_t)env->eip;
#else
  uintptr_t k = 0;
#endif

  k = (uintptr_t)(afl_hash_ip((uint64_t)k));
  k &= (CMP_MAP_W - 1);

  u32 hits = 0;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) {
    __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;
    __afl_cmp_map->headers[k].hits = 0;
    __afl_cmp_map->headers[k].shape = 30;
  } else {
    hits = __afl_cmp_map->headers[k].hits;
  }

  __afl_cmp_map->headers[k].hits += 1;

  hits &= CMP_MAP_RTN_H - 1;
  ((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v0_len = 31;
  ((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v1_len = 31;
  __builtin_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v0,
                   ptr1, 31);
  __builtin_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v1,
                   ptr2, 31);

}

/* 32-bit helpers */

int32_t HELPER(div_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 / arg2;
}

int32_t HELPER(rem_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 % arg2;
}

uint32_t HELPER(divu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 / arg2;
}

uint32_t HELPER(remu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 % arg2;
}

/* 64-bit helpers */

uint64_t HELPER(shl_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 << arg2;
}

uint64_t HELPER(shr_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(sar_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(div_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 / arg2;
}

int64_t HELPER(rem_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(divu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 / arg2;
}

uint64_t HELPER(remu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(muluh_i64)(uint64_t arg1, uint64_t arg2)
{
    uint64_t l, h;
    mulu64(&l, &h, arg1, arg2);
    return h;
}

int64_t HELPER(mulsh_i64)(int64_t arg1, int64_t arg2)
{
    uint64_t l, h;
    muls64(&l, &h, arg1, arg2);
    return h;
}

uint32_t HELPER(clz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? clz32(arg) : zero_val;
}

uint32_t HELPER(ctz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? ctz32(arg) : zero_val;
}

uint64_t HELPER(clz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? clz64(arg) : zero_val;
}

uint64_t HELPER(ctz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? ctz64(arg) : zero_val;
}

uint32_t HELPER(clrsb_i32)(uint32_t arg)
{
    return clrsb32(arg);
}

uint64_t HELPER(clrsb_i64)(uint64_t arg)
{
    return clrsb64(arg);
}

uint32_t HELPER(ctpop_i32)(uint32_t arg)
{
    return ctpop32(arg);
}

uint64_t HELPER(ctpop_i64)(uint64_t arg)
{
    return ctpop64(arg);
}

const void *HELPER(lookup_tb_ptr)(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, curr_cflags());
    if (tb == NULL) {
        return tcg_code_gen_epilogue;
    }
    qemu_log_mask_and_addr(CPU_LOG_EXEC, pc,
                           "Chain %d: %p ["
                           TARGET_FMT_lx "/" TARGET_FMT_lx "/%#x] %s\n",
                           cpu->cpu_index, tb->tc.ptr, cs_base, pc, flags,
                           lookup_symbol(pc));
    return tb->tc.ptr;
}

void HELPER(exit_atomic)(CPUArchState *env)
{
    cpu_loop_exit_atomic(env_cpu(env), GETPC());
}

/////////////////////////////////////////////////
//                  QDMSAN
/////////////////////////////////////////////////

#include "qemuafl/qdmsan-qemu.h"
#include "qemuafl/interval-tree/rbtree.h"
#include "qemuafl/interval-tree/interval_tree_generic.h"
#include <stdatomic.h>
#include <pthread.h>
#include "linux-user/qemu.h"
#include <elf.h>
#include <sys/stat.h>

struct qdmsan_qemu_fast_map *__qdmsan_qemu_map = NULL;
struct qdmsan_feedback_shm *__qdmsan_qemu_feedback_map = NULL;
struct qdmsan_qemu_full_shm *__qdmsan_qemu_full_map = NULL;
uint8_t *__qdmsan_qemu_poison = NULL;
__thread uint64_t __qdmsan_qemu_h1  = 0;
__thread uint64_t __qdmsan_qemu_h2  = 0;
static __thread uint64_t qdmsan_oob_h1;
static __thread uint64_t qdmsan_oob_h2;
static __thread uint64_t qdmsan_oob_cnt;
static __thread uint64_t qdmsan_uaf_h1;
static __thread uint64_t qdmsan_uaf_h2;
static __thread uint64_t qdmsan_uaf_cnt;
int qdmsan_check_mode = QDMSAN_CHECK_RAW;
int qdmsan_record_mode = QDMSAN_MODE_FAST;
int qdmsan_stack_poison_enabled = 1;
/* The OOB/UAF heap planes are opt-in.  When off, translation emits no access
 * helper and the REGION hypercalls leave the interval registry empty, so the
 * OOB/UAF lanes and the access ABI flags stay zero.  The preload allocator is
 * unchanged in both settings. */
int qdmsan_heap_planes_enabled = 0;
/* Upper bound (exclusive) on a single SUB RSP frame that stack poisoning fills.
 * Default 4096 keeps the historical behavior of skipping the page-probe SUB and
 * over-large frames.  AFL_QDMSAN_STACK_MAX raises it so larger single-SUB frames
 * (e.g. a 4104-byte harness frame holding a >4 KiB local buffer) are poisoned. */
unsigned qdmsan_stack_max_fill = 4096u;
int qdmsan_pointer_checks_enabled = 1;
int qdmsan_static_clean_pointer_prune_enabled = 1;
int qdmsan_syscall_checks_enabled = 1;
int qdmsan_branch_checks_enabled = 1;
int qdmsan_cmp_branch_prune_enabled = 1;
/* Static targets cannot load libqdmsan's __libc_start_main wrapper.  Start
 * recording by default, and let dynamic-preload targets disable pre-main
 * recording with QDMSAN_ACTION_PREMAIN until the wrapper enters main(). */
int qdmsan_main_started = 1;
__thread int qdmsan_recording_suppressed = 0;
static pthread_key_t qdmsan_flush_key;
static pthread_once_t qdmsan_flush_key_once = PTHREAD_ONCE_INIT;
/* Checkpoints update TLS without locks.  QEMU exclusive sections quiesce
 * those writers before a process-wide drain.  Syscall-side recording and
 * thread removal use this lock because they run outside cpu_exec(). */
struct qdmsan_thread_accumulators {
  uint64_t *lanes[9];
  struct qdmsan_thread_accumulators *next;
  bool registered;
};
static __thread struct qdmsan_thread_accumulators qdmsan_thread_acc;
static struct qdmsan_thread_accumulators *qdmsan_threads;
static pthread_mutex_t qdmsan_threads_lock = PTHREAD_MUTEX_INITIALIZER;
static bool qdmsan_process_exiting;
static bool qdmsan_paper_compat;
static _Atomic uint64_t qdmsan_fixed_time_counter;
static _Atomic uint64_t qdmsan_fixed_rand_counter;
static _Atomic uint64_t qdmsan_fixed_tsc_counter;
static _Atomic uint64_t qdmsan_fixed_rdrand_counter;

/* This registry stores only allocation-boundary/lifetime intervals supplied
 * by libqdmsan.  It is deliberately sparse (one node per region), and carries
 * no byte validity or taint state.  A hit merely routes a pre-access byte
 * digest to the OOB or UAF differential lane; it never reports a violation. */
struct qdmsan_region_node {
  struct rb_node rb;
  target_ulong start;
  target_ulong last;
  target_ulong subtree_last;
  uint8_t type;
};

#define QDMSAN_REGION_START(node) ((node)->start)
#define QDMSAN_REGION_LAST(node) ((node)->last)
INTERVAL_TREE_DEFINE(struct qdmsan_region_node, rb, target_ulong, subtree_last,
                     QDMSAN_REGION_START, QDMSAN_REGION_LAST, static,
                     qdmsan_region_tree)
#undef QDMSAN_REGION_START
#undef QDMSAN_REGION_LAST

static struct rb_root qdmsan_region_root = RB_ROOT;
static pthread_rwlock_t qdmsan_region_lock = PTHREAD_RWLOCK_INITIALIZER;
static _Atomic uint64_t qdmsan_region_count;

struct qdmsan_region_hit {
  target_ulong start;
  target_ulong last;
  uint8_t type;
};

static inline target_ulong qdmsan_interval_last(target_ulong start,
                                                 target_ulong len) {
  target_ulong tail = len - 1;
  return tail > (target_ulong)-1 - start ? (target_ulong)-1 : start + tail;
}

static int qdmsan_region_add(target_ulong start, target_ulong len,
                             target_ulong type) {
  if (!start || !len ||
      (type != QDMSAN_REGION_REDZONE && type != QDMSAN_REGION_FREED)) {
    return -TARGET_EINVAL;
  }

  struct qdmsan_region_node *fresh = calloc(1, sizeof(*fresh));
  if (!fresh) return -TARGET_ENOMEM;
  fresh->start = start;
  fresh->last = qdmsan_interval_last(start, len);
  fresh->type = (uint8_t)type;

  pthread_rwlock_wrlock(&qdmsan_region_lock);
  struct qdmsan_region_node *node = qdmsan_region_tree_iter_first(
      &qdmsan_region_root, fresh->start, fresh->last);
  while (node) {
    if (node->start == fresh->start && node->last == fresh->last &&
        node->type == fresh->type) {
      pthread_rwlock_unlock(&qdmsan_region_lock);
      free(fresh);
      return 0;
    }
    node = qdmsan_region_tree_iter_next(node, fresh->start, fresh->last);
  }
  qdmsan_region_tree_insert(fresh, &qdmsan_region_root);
  atomic_fetch_add_explicit(&qdmsan_region_count, 1, memory_order_release);
  pthread_rwlock_unlock(&qdmsan_region_lock);
  return 0;
}

static int qdmsan_region_remove(target_ulong start, target_ulong len,
                                target_ulong type) {
  if (!start || !len ||
      (type && type != QDMSAN_REGION_REDZONE && type != QDMSAN_REGION_FREED)) {
    return -TARGET_EINVAL;
  }

  target_ulong last = qdmsan_interval_last(start, len);
  uint64_t removed = 0;
  pthread_rwlock_wrlock(&qdmsan_region_lock);
  struct qdmsan_region_node *node =
      qdmsan_region_tree_iter_first(&qdmsan_region_root, start, last);
  while (node) {
    struct qdmsan_region_node *next =
        qdmsan_region_tree_iter_next(node, start, last);
    if (node->start == start && node->last == last &&
        (!type || node->type == type)) {
      qdmsan_region_tree_remove(node, &qdmsan_region_root);
      free(node);
      ++removed;
    }
    node = next;
  }
  if (removed) {
    atomic_fetch_sub_explicit(&qdmsan_region_count, removed,
                              memory_order_release);
  }
  pthread_rwlock_unlock(&qdmsan_region_lock);
  return 0;
}

/* Caller holds qdmsan_region_lock for reading.  UAF wins if stale or racing
 * metadata ever leaves a freed interval overlapping a redzone. */
static bool qdmsan_region_find_locked(target_ulong start, target_ulong last,
                                      struct qdmsan_region_hit *hit) {
  struct qdmsan_region_node *node =
      qdmsan_region_tree_iter_first(&qdmsan_region_root, start, last);
  bool found = false;
  while (node) {
    if (!found || node->type == QDMSAN_REGION_FREED) {
      hit->start = node->start > start ? node->start : start;
      hit->last = node->last < last ? node->last : last;
      hit->type = node->type;
      found = true;
      if (node->type == QDMSAN_REGION_FREED) break;
    }
    node = qdmsan_region_tree_iter_next(node, start, last);
  }
  return found;
}

static int qdmsan_ascii_lower(int c) {
  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int qdmsan_str_eq_ci(const char *s, const char *lit) {
  if (!s || !lit) return 0;
  while (*s && *lit) {
    if (qdmsan_ascii_lower((unsigned char)*s) !=
        qdmsan_ascii_lower((unsigned char)*lit)) {
      return 0;
    }
    ++s;
    ++lit;
  }
  return !*s && !*lit;
}

static uint64_t qdmsan_mix_fixed_rand(uint64_t x) {
  x += UINT64_C(0x9e3779b97f4a7c15);
  x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
  return x ^ (x >> 31);
}

uint64_t qdmsan_fixed_time_sec_next(void) {
  uint64_t base = __qdmsan_qemu_map
                      ? __qdmsan_qemu_map->fixed_time_sec
                      : UINT64_C(1704326400);
  uint64_t n =
      atomic_fetch_add_explicit(&qdmsan_fixed_time_counter, 1,
                                memory_order_relaxed);
  return base + n;
}

static uint64_t qdmsan_fixed_rand_raw_next(void) {
  uint64_t base = __qdmsan_qemu_map
                      ? __qdmsan_qemu_map->fixed_rand_base
                      : UINT64_C(0x123456789abcdef0);
  uint64_t n =
      atomic_fetch_add_explicit(&qdmsan_fixed_rand_counter, 1,
                                memory_order_relaxed);
  return base + n;
}

void qdmsan_fill_fixed_rand_bytes(void *buf, size_t len) {
  uint8_t *p = (uint8_t *)buf;
  while (len) {
    uint64_t x = qdmsan_mix_fixed_rand(qdmsan_fixed_rand_raw_next());
    for (int i = 0; i < 8 && len; ++i, --len) {
      *p++ = (uint8_t)(x >> (i * 8));
    }
  }
}

uint64_t qdmsan_fixed_tsc_next(void) {
  uint64_t base = __qdmsan_qemu_map
                      ? __qdmsan_qemu_map->fixed_tsc_base
                      : UINT64_C(0x0001000000000000);
  uint64_t n =
      atomic_fetch_add_explicit(&qdmsan_fixed_tsc_counter, 1,
                                memory_order_relaxed);
  return base + n;
}

uint64_t qdmsan_fixed_rdrand_next(void) {
  uint64_t base = __qdmsan_qemu_map
                      ? __qdmsan_qemu_map->fixed_rdrand_base
                      : UINT64_C(0xdeadbeefcafebabe);
  uint64_t n =
      atomic_fetch_add_explicit(&qdmsan_fixed_rdrand_counter, 1,
                                memory_order_relaxed);
  return base + n;
}

static const uint8_t qdmsan_run1_table[256] = {
    0x01, 0x03, 0x09, 0x1b, 0x51, 0xf3, 0xd7, 0x83, 0x88, 0x97, 0xc4, 0x4a, 0xde, 0x98, 0xc7, 0x53,
    0xf9, 0xe9, 0xb9, 0x29, 0x7b, 0x70, 0x4f, 0xed, 0xc5, 0x4d, 0xe7, 0xb3, 0x17, 0x45, 0xcf, 0x6b,
    0x40, 0xc0, 0x3e, 0xba, 0x2c, 0x84, 0x8b, 0xa0, 0xdf, 0x9b, 0xd0, 0x6e, 0x49, 0xdb, 0x8f, 0xac,
    0x02, 0x06, 0x12, 0x36, 0xa2, 0xe5, 0xad, 0x05, 0x0f, 0x2d, 0x87, 0x94, 0xbb, 0x2f, 0x8d, 0xa6,
    0xf1, 0xd1, 0x71, 0x52, 0xf6, 0xe0, 0x9e, 0xd9, 0x89, 0x9a, 0xcd, 0x65, 0x2e, 0x8a, 0x9d, 0xd6,
    0x80, 0x7f, 0x7c, 0x73, 0x58, 0x07, 0x15, 0x3f, 0xbd, 0x35, 0x9f, 0xdc, 0x92, 0xb5, 0x1d, 0x57,
    0x04, 0x0c, 0x24, 0x6c, 0x43, 0xc9, 0x59, 0x0a, 0x1e, 0x5a, 0x0d, 0x27, 0x75, 0x5e, 0x19, 0x4b,
    0xe1, 0xa1, 0xe2, 0xa4, 0xeb, 0xbf, 0x3b, 0xb1, 0x11, 0x33, 0x99, 0xca, 0x5c, 0x13, 0x39, 0xab,
    0x00, 0xfe, 0xf8, 0xe6, 0xb0, 0x0e, 0x2a, 0x7e, 0x79, 0x6a, 0x3d, 0xb7, 0x23, 0x69, 0x3a, 0xae,
    0x08, 0x18, 0x48, 0xd8, 0x86, 0x91, 0xb2, 0x14, 0x3c, 0xb4, 0x1a, 0x4e, 0xea, 0xbc, 0x32, 0x96,
    0xc1, 0x41, 0xc3, 0x47, 0xd5, 0x7d, 0x76, 0x61, 0x22, 0x66, 0x31, 0x93, 0xb8, 0x26, 0x72, 0x55,
    0xff, 0xfb, 0xef, 0xcb, 0x5f, 0x1c, 0x54, 0xfc, 0xf2, 0xd4, 0x7a, 0x6d, 0x46, 0xd2, 0x74, 0x5b,
    0x10, 0x30, 0x90, 0xaf, 0x0b, 0x21, 0x63, 0x28, 0x78, 0x67, 0x34, 0x9c, 0xd3, 0x77, 0x64, 0x2b,
    0x81, 0x82, 0x85, 0x8e, 0xa9, 0xfa, 0xec, 0xc2, 0x44, 0xcc, 0x62, 0x25, 0x6f, 0x4c, 0xe4, 0xaa,
    0xfd, 0xf5, 0xdd, 0x95, 0xbe, 0x38, 0xa8, 0xf7, 0xe3, 0xa7, 0xf4, 0xda, 0x8c, 0xa3, 0xe8, 0xb6,
    0x20, 0x60, 0x1f, 0x5d, 0x16, 0x42, 0xc6, 0x50, 0xf0, 0xce, 0x68, 0x37, 0xa5, 0xee, 0xc8, 0x56,
};

static const uint8_t qdmsan_run2_table[256] = {
    0x6f, 0x6d, 0xf7, 0x63, 0x2a, 0x42, 0x62, 0xef, 0xd4, 0xa9, 0x9b, 0x33, 0x8b, 0xe6, 0x88, 0x18,
    0xb8, 0xfe, 0xc3, 0x95, 0x03, 0x38, 0x36, 0x9a, 0xba, 0x14, 0x80, 0x89, 0x7f, 0x2c, 0xa0, 0x00,
    0x79, 0xaf, 0x09, 0xd0, 0x40, 0xc8, 0x77, 0x99, 0xaa, 0x25, 0x65, 0xd5, 0x20, 0xce, 0xf3, 0x15,
    0x6c, 0x48, 0x6a, 0xf1, 0xfb, 0x52, 0xf4, 0x5b, 0xc1, 0xe1, 0xdb, 0xea, 0x71, 0x53, 0x41, 0xcf,
    0x90, 0x84, 0x49, 0x69, 0x07, 0x17, 0xf0, 0xbc, 0x35, 0xc4, 0x72, 0x7e, 0x92, 0xf6, 0xe3, 0xa3,
    0xec, 0x87, 0x24, 0x2b, 0x23, 0x39, 0x7d, 0x78, 0x47, 0x82, 0x51, 0xe9, 0xfc, 0xdf, 0xa5, 0x3c,
    0x7a, 0xb2, 0x68, 0x97, 0x3a, 0xb6, 0xe2, 0x54, 0x66, 0x91, 0x73, 0x7b, 0x1d, 0xe5, 0xd1, 0xf2,
    0x96, 0xe8, 0x55, 0xcd, 0x8c, 0x05, 0x5c, 0xeb, 0x29, 0x64, 0x67, 0x75, 0xa7, 0x4b, 0x2e, 0x12,
    0x1e, 0x9f, 0xc9, 0x21, 0xca, 0x60, 0x56, 0x06, 0xb1, 0xa1, 0x4a, 0xdd, 0x4f, 0xd2, 0x5d, 0x57,
    0x76, 0x70, 0x81, 0xbd, 0xfa, 0xff, 0xf8, 0x7c, 0x6b, 0xae, 0xa2, 0xb7, 0x8d, 0xc6, 0x85, 0xd8,
    0xde, 0x08, 0xac, 0x5e, 0xb0, 0xc5, 0x6e, 0x1a, 0x3e, 0x0d, 0x46, 0xfd, 0x02, 0x5a, 0x0a, 0x4e,
    0xee, 0x8a, 0xa8, 0x94, 0x04, 0x44, 0x3f, 0x9d, 0x83, 0x11, 0xc2, 0x16, 0x2f, 0x27, 0x1c, 0x30,
    0x58, 0xc7, 0x8e, 0xd6, 0xb5, 0x4d, 0x28, 0x74, 0x10, 0x0c, 0x43, 0x22, 0xa6, 0x1f, 0x0f, 0xd7,
    0xed, 0x9e, 0xb9, 0x32, 0xc0, 0xab, 0xbb, 0xad, 0x2d, 0xb3, 0x59, 0x19, 0x34, 0xf5, 0x93, 0xd3,
    0x9c, 0xa4, 0x98, 0xcb, 0xe4, 0x5f, 0x61, 0x86, 0xb4, 0xbe, 0x45, 0xbf, 0xe0, 0xda, 0x8f, 0xdc,
    0x4c, 0x3b, 0xe7, 0x26, 0x0e, 0x1b, 0xf9, 0x0b, 0x31, 0x01, 0x13, 0x50, 0xcc, 0xd9, 0x37, 0x3d,
};

static inline uint8_t qdmsan_current_poison(void) {
  return __qdmsan_qemu_poison ? *__qdmsan_qemu_poison : 0x11u;
}

#define QDMSAN_SYSCALL_PC_NS UINT64_C(0xffff000000000000)
#define QDMSAN_TARGET_RLIMIT64_SIZE 16u
#define QDMSAN_FULL_SITE_INIT_SPIN_LIMIT 4096u

static inline uint64_t qdmsan_mix64(uint64_t x) {
  x ^= x >> 30;
  x *= UINT64_C(0xbf58476d1ce4e5b9);
  x ^= x >> 27;
  x *= UINT64_C(0x94d049bb133111eb);
  x ^= x >> 31;
  return x;
}

static inline size_t qdmsan_phase_quantum(uintptr_t ptr, size_t size) {
  uintptr_t q = ptr & (~ptr + 1);
  if (!q) q = 1;
  while (q > size) q >>= 1;
  if (q > 16) q = 16;
  return q ? q : 1;
}

static inline uint8_t qdmsan_start_offset(uintptr_t ptr, size_t size) {
  size_t q = qdmsan_phase_quantum(ptr, size);
  uint64_t seed = (uint64_t)ptr;
  uint8_t start = (uint8_t)(qdmsan_mix64(seed ^ ((uint64_t)size << 19) ^
                         ((uint64_t)0x5a << 56) ^
                         UINT64_C(0x9e3779b97f4a7c15)) & 0xffu);
  return (uint8_t)(start & ~((uint8_t)q - 1));
}

static void qdmsan_fill_host_for_guest(void *host, target_ulong guest,
                                       size_t size, uint8_t poison) {
  if (!host || !size) return;
  if (!poison) {
    memset(host, 0, size);
    return;
  }

  const uint8_t *table = (poison == 0x22u) ? qdmsan_run2_table
                                           : qdmsan_run1_table;
  uint8_t *p = (uint8_t *)host;
  uint8_t start = qdmsan_start_offset((uintptr_t)guest, size);

  while (size) {
    size_t chunk = size < (size_t)(256 - start) ? size : (size_t)(256 - start);
    memcpy(p, table + start, chunk);
    p += chunk;
    size -= chunk;
    start = 0;
  }
}

/* QDMSAN dump mode: write per-checkpoint (PC, arg1, arg2) to file.
 * Enabled by QDMSAN_DUMP_FILE env var.
 * File name gets _0xNN suffix from the current poison selector.
 * Uses raw fd + write() to avoid stdio buffering issues. */
static int __qdmsan_dump_fd = -1;
static int __qdmsan_dump_checked = 0;
static inline void qdmsan_dump_entry(uint64_t pc, uint64_t a1, uint64_t a2) {
  if (!__qdmsan_dump_checked) {
    __qdmsan_dump_checked = 1;
    const char *p = getenv("QDMSAN_DUMP_FILE");
    if (p && (__qdmsan_qemu_map || __qdmsan_qemu_full_map)) {
      char path[512];
      snprintf(path, sizeof(path), "%s_0x%02x", p,
               (unsigned)qdmsan_current_poison());
      __qdmsan_dump_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }
  }
  if (__qdmsan_dump_fd >= 0) {
    uint64_t entry[3] = { pc, a1, a2 };
    ssize_t written = write(__qdmsan_dump_fd, entry, sizeof(entry));
    if (written != sizeof(entry)) {
      close(__qdmsan_dump_fd);
      __qdmsan_dump_fd = -1;
    }
  }
}
__thread uint64_t __qdmsan_qemu_cnt = 0;

target_ulong qdmsan_app_start = 0;  /* 0 = range filter disabled */
target_ulong qdmsan_app_end   = 0;
target_ulong qdmsan_app_base  = 0;  /* PIE/module base for relative ranges */

int use_qdmsan = 0;
int qdmsan_max_call_stack = 8;
__thread struct qdmsan_shadow_stack qdmsan_shadow_stack;

#define QDMSAN_SUPPRESS_MAX_RANGES 256

struct qdmsan_suppress_range {
  uint64_t start;
  uint64_t end;
  int absolute;
};

static struct qdmsan_suppress_range qdmsan_suppress_ranges[QDMSAN_SUPPRESS_MAX_RANGES];
static unsigned qdmsan_suppress_range_count;

static char *qdmsan_trim_ws(char *s) {
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
  char *end = s + strlen(s);
  while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                     end[-1] == '\r' || end[-1] == '\n')) {
    *--end = 0;
  }
  return s;
}

static void qdmsan_add_suppress_range(uint64_t start, uint64_t end,
                                      int absolute) {
  if (qdmsan_suppress_range_count >= QDMSAN_SUPPRESS_MAX_RANGES) return;
  if (end < start) {
    uint64_t tmp = start;
    start = end;
    end = tmp;
  }
  qdmsan_suppress_ranges[qdmsan_suppress_range_count].start = start;
  qdmsan_suppress_ranges[qdmsan_suppress_range_count].end = end;
  qdmsan_suppress_ranges[qdmsan_suppress_range_count].absolute = absolute;
  qdmsan_suppress_range_count++;
}

static void qdmsan_parse_suppress_token(char *tok) {
  tok = qdmsan_trim_ws(tok);
  if (!*tok || *tok == '#') return;

  char *comment = strchr(tok, '#');
  if (comment) {
    *comment = 0;
    tok = qdmsan_trim_ws(tok);
    if (!*tok) return;
  }

  int absolute = 0;
  if (!strncmp(tok, "abs:", 4)) {
    absolute = 1;
    tok += 4;
  } else if (!strncmp(tok, "absolute:", 9)) {
    absolute = 1;
    tok += 9;
  } else if (!strncmp(tok, "rel:", 4)) {
    tok += 4;
  } else if (!strncmp(tok, "relative:", 9)) {
    tok += 9;
  }

  tok = qdmsan_trim_ws(tok);
  if (!*tok) return;

  errno = 0;
  char *endp = NULL;
  uint64_t start = strtoull(tok, &endp, 0);
  if (errno || endp == tok) return;

  uint64_t end = start;
  if (*endp == '-' || *endp == '+') {
    char op = *endp++;
    errno = 0;
    char *endp2 = NULL;
    uint64_t v = strtoull(endp, &endp2, 0);
    if (errno || endp2 == endp) return;
    if (op == '+') {
      end = v ? start + v - 1 : start;
    } else {
      end = v;
    }
    endp = endp2;
  }

  endp = qdmsan_trim_ws(endp);
  if (*endp) return;
  qdmsan_add_suppress_range(start, end, absolute);
}

static void qdmsan_parse_suppress_list(const char *list) {
  if (!list || !*list) return;

  char *copy = strdup(list);
  if (!copy) return;

  char *saveptr = NULL;
  for (char *tok = strtok_r(copy, ",;\n", &saveptr);
       tok;
       tok = strtok_r(NULL, ",;\n", &saveptr)) {
    qdmsan_parse_suppress_token(tok);
  }

  free(copy);
}

static void qdmsan_parse_suppress_file(const char *path) {
  if (!path || !*path) return;

  FILE *fp = fopen(path, "r");
  if (!fp) return;

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    qdmsan_parse_suppress_token(line);
  }

  fclose(fp);
}

static int qdmsan_compare_suppress_range(const void *a, const void *b) {
  const struct qdmsan_suppress_range *ra = a;
  const struct qdmsan_suppress_range *rb = b;

  if (ra->absolute != rb->absolute) return ra->absolute - rb->absolute;
  if (ra->start < rb->start) return -1;
  if (ra->start > rb->start) return 1;
  if (ra->end < rb->end) return -1;
  if (ra->end > rb->end) return 1;
  return 0;
}

static void qdmsan_finalize_suppress_ranges(void) {
  if (qdmsan_suppress_range_count < 2) return;

  qsort(qdmsan_suppress_ranges, qdmsan_suppress_range_count,
        sizeof(qdmsan_suppress_ranges[0]), qdmsan_compare_suppress_range);

  unsigned out = 0;
  for (unsigned i = 1; i < qdmsan_suppress_range_count; ++i) {
    struct qdmsan_suppress_range *cur = &qdmsan_suppress_ranges[out];
    struct qdmsan_suppress_range *next = &qdmsan_suppress_ranges[i];
    int adjacent = cur->end != UINT64_MAX && next->start == cur->end + 1;

    if (cur->absolute == next->absolute &&
        (next->start <= cur->end || adjacent)) {
      if (next->end > cur->end) cur->end = next->end;
      continue;
    }

    qdmsan_suppress_ranges[++out] = *next;
  }
  qdmsan_suppress_range_count = out + 1;
}

static inline int qdmsan_pc_suppressed(uint64_t pc) {
  if (!qdmsan_suppress_range_count) return 0;

  uint64_t rel_pc = pc;
  int have_rel = 0;
  if (qdmsan_app_base && pc >= qdmsan_app_base) {
    rel_pc = pc - qdmsan_app_base;
    have_rel = 1;
  } else if (!qdmsan_app_base) {
    have_rel = 1;
  }

  for (unsigned i = 0; i < qdmsan_suppress_range_count; ++i) {
    struct qdmsan_suppress_range *r = &qdmsan_suppress_ranges[i];
    uint64_t v = r->absolute ? pc : rel_pc;
    if ((r->absolute || have_rel) && v >= r->start && v <= r->end) {
      return 1;
    }
  }

  return 0;
}

int qdmsan_should_emit_tcg_event(target_ulong pc) {
  if (qdmsan_app_start && (pc < qdmsan_app_start || pc > qdmsan_app_end)) {
    return 0;
  }

  if (qdmsan_pc_suppressed((uint64_t)pc)) {
    return 0;
  }

  return 1;
}

static void qdmsan_dump_guest_maps(void) {
  const char *maps_path = getenv("QDMSAN_MAPS_FILE");
  if (!maps_path || !*maps_path) return;

  FILE *src = fopen("/proc/self/maps", "r");
  FILE *dst = fopen(maps_path, "w");
  if (!src || !dst) {
    if (src) fclose(src);
    if (dst) fclose(dst);
    return;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  while ((read = getline(&line, &len, src)) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";

    fields = sscanf(line,
                    "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d %512s",
                    &min, &max, &flag_r, &flag_w, &flag_x, &flag_p, &offset,
                    &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11) || !h2g_valid(min)) continue;

    int flags = page_get_flags(h2g(min));
    max = h2g_valid(max - 1) ? max : (uintptr_t)AFL_G2H(GUEST_ADDR_MAX) + 1;
    if (page_check_range(h2g(min), max - min, flags) == -1) continue;

    fprintf(dst,
            TARGET_FMT_lx "-" TARGET_FMT_lx " %c%c%c%c %"PRIx64" %x:%x %d %s\n",
            h2g(min), h2g(max), flag_r, flag_w, flag_x, flag_p, offset,
            dev_maj, dev_min, inode, fields == 11 ? path : "");
  }

  free(line);
  fclose(src);
  fclose(dst);
}

static void addr2line_cmd(char *lib, uintptr_t off, char **function,
                          char **line);

static void qdmsan_trim_trailing_newline(char *s) {

  if (!s) return;
  size_t len = strlen(s);
  while (len && (s[len - 1] == '\n' || s[len - 1] == '\r')) s[--len] = '\0';

}

static int qdmsan_fileoff_to_vaddr(const unsigned char *image, size_t size,
                                   uint64_t file_off, uint64_t *vaddr_out) {

  if (!image || size < EI_NIDENT || !vaddr_out) return -1;
  if (image[0] != ELFMAG0 || image[1] != ELFMAG1 ||
      image[2] != ELFMAG2 || image[3] != ELFMAG3) return -1;

  if (image[EI_CLASS] == ELFCLASS64) {
    if (size < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)image;
    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr) > size) return -1;
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(image + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; ++i) {
      if (ph[i].p_type != PT_LOAD) continue;
      if (file_off < ph[i].p_offset ||
          file_off >= ph[i].p_offset + ph[i].p_filesz) continue;
      *vaddr_out = (file_off - ph[i].p_offset) + ph[i].p_vaddr;
      return 0;
    }
  } else if (image[EI_CLASS] == ELFCLASS32) {
    if (size < sizeof(Elf32_Ehdr)) return -1;
    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)image;
    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(Elf32_Phdr) > size) return -1;
    const Elf32_Phdr *ph = (const Elf32_Phdr *)(image + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; ++i) {
      if (ph[i].p_type != PT_LOAD) continue;
      if (file_off < ph[i].p_offset ||
          file_off >= ph[i].p_offset + ph[i].p_filesz) continue;
      *vaddr_out = (file_off - ph[i].p_offset) + ph[i].p_vaddr;
      return 0;
    }
  }

  return -1;

}

static int qdmsan_resolve_vaddr_from_bytes(const char *path,
                                           const unsigned char *needle,
                                           size_t needle_len,
                                           uint64_t *vaddr_out) {

  if (!path || !*path || !vaddr_out || !needle || !needle_len) return -1;

  int fd = open(path, O_RDONLY);
  if (fd < 0) return -1;

  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size <= 0) {
    close(fd);
    return -1;
  }

  size_t size = (size_t)st.st_size;
  unsigned char *image = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (image == MAP_FAILED) return -1;

  uint64_t match_off = 0;
  int matches = 0;
  for (size_t i = 0; i + needle_len <= size; ++i) {
    if (memcmp(image + i, needle, needle_len)) continue;
    match_off = i;
    if (++matches > 1) break;
  }

  int rc = -1;
  if (matches == 1) {
    rc = qdmsan_fileoff_to_vaddr(image, size, match_off, vaddr_out);
  }

  munmap(image, size);
  return rc;

}

static void qdmsan_emit_symbolized_guest_addr(FILE *out, const char *kind,
                                              int index,
                                              target_ulong guest_addr) {

  if (!out || !kind || !*kind || !guest_addr) return;

  if (!strcmp(kind, "SITE")) {
    fprintf(out, "SITE %llx\n", (unsigned long long)guest_addr);
  } else {
    fprintf(out, "FRAME %d %llx\n", index, (unsigned long long)guest_addr);
  }

  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) return;

  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  while ((read = getline(&line, &len, fp)) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line,
                    "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d %512s",
                    &min, &max, &flag_r, &flag_w, &flag_x, &flag_p, &offset,
                    &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11)) continue;
    if (!h2g_valid(min)) continue;

    int flags = page_get_flags(h2g(min));
    max = h2g_valid(max - 1) ? max : (uintptr_t)AFL_G2H(GUEST_ADDR_MAX) + 1;
    if (page_check_range(h2g(min), max - min, flags) == -1) continue;

    if (guest_addr < h2g(min) || guest_addr >= h2g(max - 1) + 1) continue;

    uintptr_t base = h2g(min) - offset;
    uintptr_t off = guest_addr - base;
    uint64_t live_vaddr = 0;
    int live_rc = -1;
    if (path[0] && thread_cpu && access_ok(thread_cpu, VERIFY_READ, guest_addr, 8)) {
      const unsigned char *guest = g2h(thread_cpu, guest_addr);
      if (guest) {
        live_rc = qdmsan_resolve_vaddr_from_bytes(path, guest, 8, &live_vaddr);
      }
    }
    if (live_rc == 0) {
      off = (uintptr_t)live_vaddr;
      base = guest_addr - off;
    }
    fprintf(out, "MODULE %s %llx %llx\n", path,
            (unsigned long long)base, (unsigned long long)off);

    if (path[0]) {
      char *function = NULL;
      char *codeline = NULL;
      addr2line_cmd(path, off, &function, &codeline);
      if (!function) addr2line_cmd(path, guest_addr, &function, &codeline);

      if (function) {
        qdmsan_trim_trailing_newline(function);
        if (*function) fprintf(out, "FUNCTION %s\n", function);
      }
      if (codeline) {
        qdmsan_trim_trailing_newline(codeline);
        if (*codeline) fprintf(out, "LOCATION %s\n", codeline);
      }

      free(function);
      free(codeline);
    }

    break;
  }

  free(line);
  fclose(fp);

}

static void qdmsan_lookup_guest_pc(void) {
  const char *pc_env = getenv("QDMSAN_LOOKUP_PC");
  const char *out_env = getenv("QDMSAN_LOOKUP_OUT");
  if (!pc_env || !*pc_env || !out_env || !*out_env) return;

  target_ulong guest_addr = (target_ulong)strtoull(pc_env, NULL, 0);
  FILE *fp = fopen("/proc/self/maps", "r");
  FILE *out = fopen(out_env, "w");
  if (!fp || !out) {
    if (fp) fclose(fp);
    if (out) fclose(out);
    return;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  uint64_t img_min = 0;
  char img_path[512] = {0};

  while ((read = getline(&line, &len, fp)) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line, "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d %512s",
                    &min, &max, &flag_r, &flag_w, &flag_x, &flag_p, &offset,
                    &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11)) continue;
    if (!h2g_valid(min)) continue;

    int flags = page_get_flags(h2g(min));
    max = h2g_valid(max - 1) ? max : (uintptr_t)AFL_G2H(GUEST_ADDR_MAX) + 1;
    if (page_check_range(h2g(min), max - min, flags) == -1) continue;

    if (img_min && !strcmp(img_path, path)) {
      ;
    } else {
      img_min = min;
      strncpy(img_path, path, sizeof(img_path) - 1);
      img_path[sizeof(img_path) - 1] = 0;
    }

    if (guest_addr >= h2g(min) && guest_addr < h2g(max - 1) + 1) {
      uintptr_t base = h2g(img_min);
      uintptr_t off = guest_addr - base;
      (void)base;
      (void)off;
      qdmsan_emit_symbolized_guest_addr(out, "SITE", -1, guest_addr);
      if (qdmsan_shadow_stack.first && qdmsan_max_call_stack > 0) {
        int emitted = 0;
        struct qdmsan_shadow_stack_block *b = qdmsan_shadow_stack.first;
        for (int i = b->index - 1; i >= 0 && emitted < qdmsan_max_call_stack; --i) {
          qdmsan_emit_symbolized_guest_addr(out, "FRAME", emitted, b->buf[i]);
          emitted++;
        }
        b = b->next;
        while (b && emitted < qdmsan_max_call_stack) {
          for (int i = QDMSAN_SHADOW_BK_SIZE - 1; i >= 0 &&
                                          emitted < qdmsan_max_call_stack; --i) {
            qdmsan_emit_symbolized_guest_addr(out, "FRAME", emitted, b->buf[i]);
            emitted++;
          }
          b = b->next;
        }
      }
      break;
    }
  }

  free(line);
  fclose(fp);
  fclose(out);
}

/* Caller owns this thread, or has stopped TCG execution and holds the
 * registry lock.  Zero after publication so thread exit cannot add twice. */
static void qdmsan_flush_accumulators(struct qdmsan_thread_accumulators *acc) {
  if (!__qdmsan_qemu_map || !acc->registered) return;
  uint64_t *dest[9] = {
      &__qdmsan_qemu_map->sum_signature,
      &__qdmsan_qemu_map->rotl_signature,
      &__qdmsan_qemu_map->total_count,
      &__qdmsan_qemu_map->padding[QDMSAN_OOB_SUM_LANE],
      &__qdmsan_qemu_map->padding[QDMSAN_OOB_ROTL_LANE],
      &__qdmsan_qemu_map->padding[QDMSAN_OOB_COUNT_LANE],
      &__qdmsan_qemu_map->padding[QDMSAN_UAF_SUM_LANE],
      &__qdmsan_qemu_map->padding[QDMSAN_UAF_ROTL_LANE],
      &__qdmsan_qemu_map->padding[QDMSAN_UAF_COUNT_LANE]};
  for (unsigned plane = 0; plane < 9; plane += 3) {
    if (*acc->lanes[plane + 2]) {
      for (unsigned i = plane; i < plane + 3; ++i) {
        atomic_fetch_add((_Atomic uint64_t *)dest[i], *acc->lanes[i]);
        *acc->lanes[i] = 0;
      }
    }
  }
}

static void qdmsan_thread_flush_destructor(void *value) {
  struct qdmsan_thread_accumulators *acc = value;
  if (!acc) return;
  pthread_mutex_lock(&qdmsan_threads_lock);
  qdmsan_flush_accumulators(acc);
  struct qdmsan_thread_accumulators **link = &qdmsan_threads;
  while (*link && *link != acc) link = &(*link)->next;
  if (*link) *link = acc->next;
  acc->registered = false;
  pthread_mutex_unlock(&qdmsan_threads_lock);
}

static void qdmsan_make_flush_key(void) {
  if (pthread_key_create(&qdmsan_flush_key, qdmsan_thread_flush_destructor)) {
    abort();
  }
}

static inline void qdmsan_mark_thread_for_flush(void) {
  if (likely(qdmsan_thread_acc.registered)) return;
  pthread_once(&qdmsan_flush_key_once, qdmsan_make_flush_key);
  uint64_t *lanes[9] = {
      &__qdmsan_qemu_h1, &__qdmsan_qemu_h2, &__qdmsan_qemu_cnt,
      &qdmsan_oob_h1, &qdmsan_oob_h2, &qdmsan_oob_cnt,
      &qdmsan_uaf_h1, &qdmsan_uaf_h2, &qdmsan_uaf_cnt};
  memcpy(qdmsan_thread_acc.lanes, lanes, sizeof(lanes));
  if (pthread_setspecific(qdmsan_flush_key, &qdmsan_thread_acc)) abort();
  pthread_mutex_lock(&qdmsan_threads_lock);
  qdmsan_thread_acc.next = qdmsan_threads;
  qdmsan_threads = &qdmsan_thread_acc;
  qdmsan_thread_acc.registered = true;
  pthread_mutex_unlock(&qdmsan_threads_lock);
}

static void qdmsan_flush_all_locked(void) {
  for (struct qdmsan_thread_accumulators *acc = qdmsan_threads;
       acc; acc = acc->next) {
    qdmsan_flush_accumulators(acc);
  }
}

/* Guest fork already owns the QEMU exclusive section.  Drain before the
 * address space is copied: pre-fork events belong to the shared map once. */
void qdmsan_qemu_fork_start(void) {
  pthread_mutex_lock(&qdmsan_threads_lock);
  if (!qdmsan_paper_compat) qdmsan_flush_all_locked();
}

void qdmsan_qemu_fork_end(int child) {
  if (child) {
    qdmsan_threads = qdmsan_thread_acc.registered ? &qdmsan_thread_acc : NULL;
    qdmsan_thread_acc.next = NULL;
  }
  pthread_mutex_unlock(&qdmsan_threads_lock);
}

static inline void qdmsan_record(uint64_t v, uint32_t site_id) {
  qdmsan_mark_thread_for_flush();
  uint64_t site_salt = (uint64_t)site_id << 32;
  __qdmsan_qemu_h1 += qdmsan_mix64(v ^ (site_salt ^ QDMSAN_POLY_R1));
  __qdmsan_qemu_h2 += qdmsan_mix64(v ^ (site_salt ^ QDMSAN_POLY_R2));
  __qdmsan_qemu_cnt++;
}

static inline uint64_t qdmsan_rotl64(uint64_t v, unsigned shift) {
  return (v << shift) | (v >> (64 - shift));
}

static inline uint64_t qdmsan_combine2(uint64_t a, uint64_t b) {
  return qdmsan_rotl64(a, 1) ^ b;
}

static inline uint64_t qdmsan_combine_values(const uint64_t *values,
                                             unsigned count) {
  if (!count) return 0;
  uint64_t combined = values[0];
  for (unsigned i = 1; i < count; ++i) {
    combined = qdmsan_combine2(combined, values[i]);
  }
  return combined;
}

static inline uint32_t qdmsan_site_id(uint64_t pc, uint32_t kind,
                                      uint32_t size) {
  uint64_t x = pc;
  x ^= (uint64_t)kind * UINT64_C(0x9e3779b185ebca87);
  x ^= (uint64_t)size * UINT64_C(0xc2b2ae3d27d4eb4f);
  return QDMSAN_FEEDBACK_RUNTIME_SITE_NS |
         (uint32_t)(qdmsan_mix64(x) & 0x7fffffffu);
}

static inline void qdmsan_record_aux(uint32_t site_id, uint64_t value) {
  if (!__qdmsan_qemu_feedback_map) return;

  uint32_t idx = site_id & (QDMSAN_SITE_CLASS_ENTRIES - 1);
  uint64_t mixed = qdmsan_mix64(value);
  uint16_t bucket = (uint16_t)1u << (mixed &
                                     (QDMSAN_SITE_CLASS_BUCKETS - 1));
  uint8_t map_bucket = (uint8_t)1u << (mixed & 7u);
  atomic_fetch_or((_Atomic uint16_t *)
                      &__qdmsan_qemu_feedback_map->site_map[idx],
                  bucket);
  atomic_fetch_or((_Atomic uint8_t *)
                      &__qdmsan_qemu_feedback_map->map[idx],
                  map_bucket);
}

static inline void qdmsan_record_full(uint64_t pc, uint64_t value,
                                      uint32_t site_id) {
  if (!__qdmsan_qemu_full_map) return;

  uint64_t array_size = __qdmsan_qemu_full_map->meta.array_size;
  if (!array_size) return;

  atomic_fetch_add((_Atomic uint64_t *)
                       &__qdmsan_qemu_full_map->meta.total_count,
                   1);

  uint64_t slot = qdmsan_mix64(((uint64_t)site_id << 32) ^ pc) &
                  (array_size - 1);
  struct qdmsan_qemu_full_entry *entry =
      &__qdmsan_qemu_full_map->entries[slot];
  uint64_t module_base = __qdmsan_qemu_full_map->meta.module_base;
  uint64_t rel_pc = (module_base && pc < QDMSAN_SYSCALL_PC_NS &&
                     pc >= module_base)
                        ? pc - module_base
                        : pc;

  _Atomic uint32_t *site_ptr = (_Atomic uint32_t *)&entry->site_id;
  uint32_t observed = atomic_load_explicit(site_ptr, memory_order_acquire);

  if (!observed) {
    uint32_t expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            site_ptr, &expected, 1u, memory_order_acquire,
            memory_order_relaxed)) {
      entry->pc = rel_pc;
      entry->flags = 0;
      entry->reserved = 0;
      atomic_store_explicit(site_ptr, site_id, memory_order_release);
      atomic_fetch_add((_Atomic uint64_t *)&entry->value, value);
      return;
    }
    observed = expected;
  }

  for (unsigned spin = 0;
       observed == 1u && spin < QDMSAN_FULL_SITE_INIT_SPIN_LIMIT; ++spin) {
    cpu_relax();
    observed = atomic_load_explicit(site_ptr, memory_order_acquire);
  }

  if (observed == 1u) {
    atomic_fetch_add(
        (_Atomic uint64_t *)&__qdmsan_qemu_full_map->meta.overflow_count, 1);
    return;
  }

  if (observed == site_id && entry->pc == rel_pc) {
    atomic_fetch_add((_Atomic uint64_t *)&entry->value, value);
  } else {
    atomic_fetch_or((_Atomic uint32_t *)&entry->flags,
                    QDMSAN_FULL_ENTRY_FLAG_COLLISION);
    atomic_fetch_add(
        (_Atomic uint64_t *)&__qdmsan_qemu_full_map->meta.overflow_count, 1);
  }
}

static inline void qdmsan_record_event(uint64_t pc, uint64_t value,
                                       uint32_t kind, uint32_t size) {
  if (!qdmsan_main_started) return;
  if (qdmsan_recording_suppressed) return;
  if (value == 0) return;

  /* AFL++ still uses the fast digest as the online oracle in full mode; the
     full map is the localization/reporting plane. */
  int record_fast = __qdmsan_qemu_map != NULL;
  int record_aux = __qdmsan_qemu_feedback_map &&
                   qdmsan_record_mode == QDMSAN_MODE_FAST_AUX;
  int record_full = __qdmsan_qemu_full_map &&
                    qdmsan_record_mode == QDMSAN_MODE_FULL;
  if (!record_fast && !record_aux && !record_full) return;

  uint32_t site_id = 0;
  if (record_fast || record_aux || record_full) {
    site_id = qdmsan_site_id(pc, kind, size);
  }

  if (record_fast) qdmsan_record(value, site_id);
  if (record_aux) qdmsan_record_aux(site_id, value);
  if (record_full) qdmsan_record_full(pc, value, site_id);
}

static inline void qdmsan_record_event_filtered(uint64_t pc, uint64_t value,
                                                uint32_t kind, uint32_t size) {
  if (qdmsan_app_start && pc < QDMSAN_SYSCALL_PC_NS &&
      (pc < qdmsan_app_start || pc > qdmsan_app_end)) {
    return;
  }
  if (unlikely(qdmsan_suppress_range_count) && pc < QDMSAN_SYSCALL_PC_NS &&
      qdmsan_pc_suppressed(pc)) {
    return;
  }

  qdmsan_record_event(pc, value, kind, size);
}

#define QDMSAN_ACCESS_MAX_BYTES 64u
#define QDMSAN_ACCESS_KIND_OOB  UINT32_C(0x10001)
#define QDMSAN_ACCESS_KIND_UAF  UINT32_C(0x10002)

static inline void qdmsan_record_access_plane(uint8_t type, uint64_t value,
                                              uint32_t size,
                                              bool is_store) {
  uint32_t kind = type == QDMSAN_REGION_FREED ? QDMSAN_ACCESS_KIND_UAF
                                               : QDMSAN_ACCESS_KIND_OOB;
  if (is_store) kind |= UINT32_C(0x100);
  /* Generic TCG memory helpers cannot use PC_GET(env) as an oracle input:
   * the architecture PC is lazy state and can differ at the same guest
   * instruction across forkserver children depending on TB chaining/cache
   * history.  Plane/op/width plus the preimage form the stable predicate;
   * address and dynamic PC are deliberately excluded. */
  uint64_t event_salt = ((uint64_t)kind << 32) | (uint64_t)size;
  uint64_t h1 = qdmsan_mix64(value ^ event_salt ^ QDMSAN_POLY_R1);
  uint64_t h2 = qdmsan_mix64(value ^ event_salt ^ QDMSAN_POLY_R2);

  qdmsan_mark_thread_for_flush();
  if (type == QDMSAN_REGION_FREED) {
    qdmsan_uaf_h1 += h1;
    qdmsan_uaf_h2 += h2;
    ++qdmsan_uaf_cnt;
  } else {
    qdmsan_oob_h1 += h1;
    qdmsan_oob_h2 += h2;
    ++qdmsan_oob_cnt;
  }
}

/* Runs immediately before the guest access.  In particular, a store hashes
 * the bytes it is about to overwrite, so a write-only OOB/UAF still depends
 * on the run's poison selector.  The effective address is intentionally not
 * part of the digest: heap placement is not a vulnerability predicate. */
void HELPER(qdmsan_access)(CPUArchState *env, target_ulong addr,
                           target_ulong size, target_ulong is_store) {
  if (!__qdmsan_qemu_map || !qdmsan_main_started ||
      qdmsan_recording_suppressed || !size ||
      !atomic_load_explicit(&qdmsan_region_count, memory_order_acquire)) {
    return;
  }

  target_ulong last = qdmsan_interval_last(addr, size);
  struct qdmsan_region_hit hit;
  uint8_t bytes[QDMSAN_ACCESS_MAX_BYTES];
  uint8_t offsets[QDMSAN_ACCESS_MAX_BYTES];
  unsigned nread = 0;

  pthread_rwlock_rdlock(&qdmsan_region_lock);
  if (!qdmsan_region_find_locked(addr, last, &hit)) {
    pthread_rwlock_unlock(&qdmsan_region_lock);
    return;
  }

  target_ulong hit_len = hit.last - hit.start + 1;
  if (hit_len > QDMSAN_ACCESS_MAX_BYTES) hit_len = QDMSAN_ACCESS_MAX_BYTES;
  CPUState *cpu = env_cpu(env);
  if (access_ok(cpu, VERIFY_READ, hit.start, hit_len)) {
    memcpy(bytes, AFL_G2H(hit.start), (size_t)hit_len);
    for (target_ulong i = 0; i < hit_len; ++i) {
      offsets[nread++] = (uint8_t)((hit.start - addr) + i);
    }
  } else {
    /* Do not turn a cross-page/faulting target access into a QDMSAN helper
     * crash.  Registered heap regions should normally take the fast path. */
    for (target_ulong i = 0; i < hit_len; ++i) {
      target_ulong cur = hit.start + i;
      if (!access_ok(cpu, VERIFY_READ, cur, 1)) continue;
      bytes[nread] = *(const uint8_t *)AFL_G2H(cur);
      offsets[nread++] = (uint8_t)(cur - addr);
    }
  }
  pthread_rwlock_unlock(&qdmsan_region_lock);
  if (!nread) return;

  uint64_t value = UINT64_C(1469598103934665603);
  value ^= (uint64_t)size | ((uint64_t)!!is_store << 32) |
           ((uint64_t)nread << 40);
  value *= UINT64_C(1099511628211);
  for (unsigned i = 0; i < nread; ++i) {
    value ^= (uint64_t)bytes[i] | ((uint64_t)offsets[i] << 8);
    value *= UINT64_C(1099511628211);
  }

  /* PC/range suppression is intentionally not consulted for this plane:
   * PC_GET(env) is lazy at generic memory helpers and changed between the
   * first and later forkserver children in testing.  Explicit TLS suppression
   * remains available to the allocator/runtime and is checked above. */
  qdmsan_record_access_plane(hit.type, value, (uint32_t)size, !!is_store);
}

void qdmsan_qemu_flush(void) {
  pthread_mutex_lock(&qdmsan_threads_lock);
  qdmsan_flush_accumulators(&qdmsan_thread_acc);
  pthread_mutex_unlock(&qdmsan_threads_lock);

  qdmsan_dump_guest_maps();
  qdmsan_lookup_guest_pc();
}

/* Called only outside cpu_exec, immediately before normal process exit.
 * Keep the exclusive section until exit_group kills the stopped CPUs.
 * Syscall writers can finish before the drain, or observe process_exiting
 * after it, but cannot race with reads of their TLS accumulators. */
void qdmsan_qemu_flush_process(void) {
  if (!use_qdmsan || qdmsan_paper_compat) {
    qdmsan_qemu_flush();
    return;
  }
  start_exclusive();
  pthread_mutex_lock(&qdmsan_threads_lock);
  qdmsan_process_exiting = true;
  qdmsan_flush_all_locked();
  pthread_mutex_unlock(&qdmsan_threads_lock);
  qdmsan_dump_guest_maps();
  qdmsan_lookup_guest_pc();
}

static void qdmsan_qemu_atexit(void) {
  qdmsan_qemu_flush();
  if (__qdmsan_dump_fd >= 0) { close(__qdmsan_dump_fd); __qdmsan_dump_fd = -1; }
}

void HELPER(qdmsan_shadow_stack_push)(target_ulong ptr) {
  if (unlikely(!qdmsan_shadow_stack.first)) {
    qdmsan_shadow_stack.first = malloc(sizeof(struct qdmsan_shadow_stack_block));
    qdmsan_shadow_stack.first->index = 0;
    qdmsan_shadow_stack.size = 0;
    qdmsan_shadow_stack.first->next = NULL;
  }

  qdmsan_shadow_stack.first->buf[qdmsan_shadow_stack.first->index++] = ptr;
  qdmsan_shadow_stack.size++;

  if (qdmsan_shadow_stack.first->index >= QDMSAN_SHADOW_BK_SIZE) {
    struct qdmsan_shadow_stack_block *ns =
        malloc(sizeof(struct qdmsan_shadow_stack_block));
    ns->next = qdmsan_shadow_stack.first;
    ns->index = 0;
    qdmsan_shadow_stack.first = ns;
  }
}

void HELPER(qdmsan_shadow_stack_pop)(target_ulong ptr) {
  struct qdmsan_shadow_stack_block *cur_bk = qdmsan_shadow_stack.first;
  if (unlikely(cur_bk == NULL)) return;

  do {
    cur_bk->index--;
    qdmsan_shadow_stack.size--;

    if (cur_bk->index < 0) {
      struct qdmsan_shadow_stack_block *ns = cur_bk->next;
      free(cur_bk);
      cur_bk = ns;
      if (!cur_bk) break;
      cur_bk->index--;
    }
  } while (cur_bk->buf[cur_bk->index] != ptr);

  qdmsan_shadow_stack.first = cur_bk;
}

void qdmsan_qemu_init(void) {
  const char *s = getenv(QDMSAN_FAST_SHM_ENV_VAR);
  const char *lookup_pc = getenv("QDMSAN_LOOKUP_PC");
  const char *lookup_out = getenv("QDMSAN_LOOKUP_OUT");
  const char *maps_out = getenv("QDMSAN_MAPS_FILE");
  const char *mode = getenv("AFL_QDMSAN_MODE");
  const char *check_mode = getenv("AFL_QDMSAN_CHECK");
  const char *legacy_check_mode = getenv("QDMSAN_CHECK_MODE");
  const char *stack_env = getenv("AFL_QDMSAN_STACK");
  const char *ptr_env = getenv("AFL_QDMSAN_CHECK_POINTERS");
  const char *sys_env = getenv("AFL_QDMSAN_CHECK_SYSCALLS");
  const char *branch_env = getenv("AFL_QDMSAN_CHECK_BRANCHES");
  const char *cmp_branch_prune_env = getenv("AFL_QDMSAN_CMP_BRANCH_PRUNE");
  const char *suppress_ranges_env = getenv("AFL_QDMSAN_SUPPRESS_RANGES");
  const char *suppress_file_env = getenv("AFL_QDMSAN_SUPPRESS_FILE");
  const char *stack_max_env = getenv("AFL_QDMSAN_STACK_MAX");
  const char *paper_compat_env = getenv("AFL_QDMSAN_PAPER_COMPAT");
  qdmsan_paper_compat = paper_compat_env && !strcmp(paper_compat_env, "1");

  if (!mode || !*mode || qdmsan_str_eq_ci(mode, "fast")) {
    qdmsan_record_mode = QDMSAN_MODE_FAST;
  } else if (qdmsan_str_eq_ci(mode, "fast+aux")) {
    qdmsan_record_mode = QDMSAN_MODE_FAST_AUX;
  } else if (qdmsan_str_eq_ci(mode, "full")) {
    qdmsan_record_mode = QDMSAN_MODE_FULL;
  } else {
    fprintf(stderr,
            "QDMSAN: unknown AFL_QDMSAN_MODE '%s' (expected fast|fast+aux|full)\n",
            mode);
    _exit(1);
  }

  if (!check_mode) check_mode = legacy_check_mode;
  if (qdmsan_str_eq_ci(check_mode, "result")) {
    qdmsan_check_mode = QDMSAN_CHECK_RESULT;
  } else {
    qdmsan_check_mode = QDMSAN_CHECK_RAW;
  }

  if (stack_env && (!strcmp(stack_env, "0") || !strcmp(stack_env, "off"))) {
    qdmsan_stack_poison_enabled = 0;
  }
  {
    const char *heap_env = getenv("AFL_QDMSAN_HEAP_PLANES");
    qdmsan_heap_planes_enabled =
        heap_env && (!strcmp(heap_env, "1") || qdmsan_str_eq_ci(heap_env, "on") ||
                     qdmsan_str_eq_ci(heap_env, "true") ||
                     qdmsan_str_eq_ci(heap_env, "yes"));
  }
  if (stack_max_env && *stack_max_env) {
    char *end = NULL;
    unsigned long v = strtoul(stack_max_env, &end, 0);
    /* Clamp to [4096, 1 MiB]; below a page there is nothing extra to gain and
     * an unbounded value would try to fill runaway frames. */
    if (end && *end == '\0' && v >= 4096ul) {
      if (v > (1ul << 20)) v = (1ul << 20);
      qdmsan_stack_max_fill = (unsigned)v;
    }
  }
  if (ptr_env && (!strcmp(ptr_env, "0") || !strcmp(ptr_env, "off"))) {
    qdmsan_pointer_checks_enabled = 0;
  } else if (ptr_env && !strcmp(ptr_env, "all")) {
    qdmsan_static_clean_pointer_prune_enabled = 0;
  }
  if (sys_env && (!strcmp(sys_env, "0") || !strcmp(sys_env, "off"))) {
    qdmsan_syscall_checks_enabled = 0;
  }
  if (branch_env && (!strcmp(branch_env, "0") || !strcmp(branch_env, "off"))) {
    qdmsan_branch_checks_enabled = 0;
  }
  if (cmp_branch_prune_env &&
      (!strcmp(cmp_branch_prune_env, "0") ||
       !strcmp(cmp_branch_prune_env, "off"))) {
    qdmsan_cmp_branch_prune_enabled = 0;
  }
  qdmsan_parse_suppress_list(suppress_ranges_env);
  qdmsan_parse_suppress_file(suppress_file_env);
  qdmsan_finalize_suppress_ranges();

  if (s) {
    int id = atoi(s);
    __qdmsan_qemu_map = (struct qdmsan_qemu_fast_map *)shmat(id, NULL, 0);
    if (__qdmsan_qemu_map == (void *)-1) {
      __qdmsan_qemu_map = NULL;
    }
  }

  const char *poison_s = getenv(QDMSAN_POISON_SHM_ENV_VAR);
  if (poison_s) {
    int poison_id = atoi(poison_s);
    __qdmsan_qemu_poison = (uint8_t *)shmat(poison_id, NULL, 0);
    if (__qdmsan_qemu_poison == (void *)-1) {
      __qdmsan_qemu_poison = NULL;
    }
  }

  const char *feedback_s = getenv(QDMSAN_FEEDBACK_SHM_ENV_VAR);
  if (feedback_s) {
    int feedback_id = atoi(feedback_s);
    __qdmsan_qemu_feedback_map =
        (struct qdmsan_feedback_shm *)shmat(feedback_id, NULL, 0);
    if (__qdmsan_qemu_feedback_map == (void *)-1) {
      __qdmsan_qemu_feedback_map = NULL;
    }
  }

  const char *full_s = getenv(QDMSAN_FULL_SHM_ENV_VAR);
  if (full_s) {
    int full_id = atoi(full_s);
    __qdmsan_qemu_full_map =
        (struct qdmsan_qemu_full_shm *)shmat(full_id, NULL, 0);
    if (__qdmsan_qemu_full_map == (void *)-1) {
      __qdmsan_qemu_full_map = NULL;
    }
  }
  if (!__qdmsan_qemu_map && !__qdmsan_qemu_full_map &&
      !(lookup_pc && *lookup_pc && lookup_out && *lookup_out) &&
      !(maps_out && *maps_out)) {
    return;
  }
  atexit(qdmsan_qemu_atexit);
}

/* Helper macro: skip checkpoint if PC is outside app code segment.
 * qdmsan_app_start == 0 means the range filter is disabled (default). */
#define QDMSAN_APP_FILTER(pc) \
  if (qdmsan_app_start && ((pc) < qdmsan_app_start || (pc) > qdmsan_app_end)) return;

/* libqdmsan can disable pre-main recording with the QDMSAN fake syscall and
 * re-enable it from its __libc_start_main wrapper. Static targets without the
 * preload library keep qdmsan_main_started=1 and record from program entry. */
#define QDMSAN_MAIN_FILTER() \
  if (!qdmsan_main_started) return;

static inline void qdmsan_record_cmp_raw(uint64_t pc, uint64_t a, uint64_t b,
                                         uint32_t kind, uint32_t size) {
  qdmsan_record_event(pc, qdmsan_combine2(a, b), kind, size);
}

static inline void qdmsan_record_cmp_outcome(uint64_t pc, uint64_t outcome,
                                             uint32_t kind, uint32_t size) {
  qdmsan_record_event(pc, outcome, kind | 0x200u, size);
}

static inline int qdmsan_has_recording_map(void) {
  return __qdmsan_qemu_map || __qdmsan_qemu_feedback_map ||
         __qdmsan_qemu_full_map;
}

static uint64_t qdmsan_hash_guest_bytes(target_ulong addr, target_ulong len) {
  if (!addr || !len || !thread_cpu) return UINT64_C(0);

  target_ulong limit = len < 256 ? len : 256;
  if (!access_ok(thread_cpu, VERIFY_READ, addr, limit)) return UINT64_C(0);

  const uint8_t *p = AFL_G2H(addr);
  uint64_t h = UINT64_C(1469598103934665603) ^ (uint64_t)len;
  for (target_ulong i = 0; i < limit; ++i) {
    h ^= (uint64_t)p[i];
    h *= UINT64_C(1099511628211);
  }
  return h;
}

static uint64_t qdmsan_hash_guest_cstr(target_ulong addr) {
  if (!addr || !thread_cpu) return UINT64_C(0);

  uint64_t h = UINT64_C(1469598103934665603);
  for (target_ulong i = 0; i < 256; ++i) {
    target_ulong cur = addr + i;
    if (!access_ok(thread_cpu, VERIFY_READ, cur, 1)) break;
    uint8_t c = *(uint8_t *)AFL_G2H(cur);
    h ^= (uint64_t)c;
    h *= UINT64_C(1099511628211);
    if (!c) break;
  }
  return h;
}

static uint64_t qdmsan_hash_guest_iovec(target_ulong iov_addr,
                                        target_ulong iovcnt) {
  if (!iov_addr || !iovcnt || !thread_cpu) return UINT64_C(0);

  target_ulong limit = iovcnt < 64 ? iovcnt : 64;
  size_t bytes = (size_t)limit * sizeof(struct target_iovec);
  if (!access_ok(thread_cpu, VERIFY_READ, iov_addr, bytes)) return UINT64_C(0);

  const struct target_iovec *iov = AFL_G2H(iov_addr);
  uint64_t h = UINT64_C(1469598103934665603) ^ (uint64_t)iovcnt;
  for (target_ulong i = 0; i < limit; ++i) {
    target_ulong base = (target_ulong)tswapal(iov[i].iov_base);
    target_ulong len = (target_ulong)tswapal(iov[i].iov_len);
    h ^= qdmsan_hash_guest_bytes(base, len);
    h *= UINT64_C(1099511628211);
  }
  return h;
}

static uint64_t qdmsan_hash_guest_msghdr_iov(target_ulong msg_addr) {
  if (!msg_addr || !thread_cpu) return UINT64_C(0);
  if (!access_ok(thread_cpu, VERIFY_READ, msg_addr,
                 sizeof(struct target_msghdr))) {
    return UINT64_C(0);
  }

  const struct target_msghdr *msg = AFL_G2H(msg_addr);
  return qdmsan_hash_guest_iovec((target_ulong)tswapal(msg->msg_iov),
                                 (target_ulong)tswapal(msg->msg_iovlen));
}

static uint64_t qdmsan_stable_syscall_arg(int num, unsigned idx,
                                          target_ulong value) {
  if (idx == 1) {
#ifdef TARGET_NR_process_vm_readv
    if (num == TARGET_NR_process_vm_readv && value == (target_ulong)getpid()) {
      return UINT64_C(0x51504d53504d5244);
    }
#endif
#ifdef TARGET_NR_process_vm_writev
    if (num == TARGET_NR_process_vm_writev && value == (target_ulong)getpid()) {
      return UINT64_C(0x51504d53504d5752);
    }
#endif
  }

  return (uint64_t)value;
}

static int qdmsan_prlimit64_reads_new_limit(target_ulong resource) {
#ifdef TARGET_RLIMIT_AS
  if (resource == TARGET_RLIMIT_AS) return 0;
#endif
#ifdef TARGET_RLIMIT_DATA
  if (resource == TARGET_RLIMIT_DATA) return 0;
#endif
#ifdef TARGET_RLIMIT_STACK
  if (resource == TARGET_RLIMIT_STACK) return 0;
#endif
  return 1;
}

/* Record only arguments that are part of the syscall ABI.  Unused register
 * slots contain caller scratch values and are not MSan/DMSAN use-points. */
static int qdmsan_syscall_arity(int num) {
  switch (num) {
#ifdef TARGET_NR_read
    case TARGET_NR_read: return 3;
#endif
#ifdef TARGET_NR_write
    case TARGET_NR_write: return 3;
#endif
#ifdef TARGET_NR_open
    case TARGET_NR_open: return 3;
#endif
#ifdef TARGET_NR_close
    case TARGET_NR_close: return 1;
#endif
#ifdef TARGET_NR_stat
    case TARGET_NR_stat: return 2;
#endif
#ifdef TARGET_NR_fstat
    case TARGET_NR_fstat: return 2;
#endif
#ifdef TARGET_NR_lstat
    case TARGET_NR_lstat: return 2;
#endif
#ifdef TARGET_NR_lseek
    case TARGET_NR_lseek: return 3;
#endif
#ifdef TARGET_NR_mmap
    case TARGET_NR_mmap: return 6;
#endif
#ifdef TARGET_NR_mprotect
    case TARGET_NR_mprotect: return 3;
#endif
#ifdef TARGET_NR_munmap
    case TARGET_NR_munmap: return 2;
#endif
#ifdef TARGET_NR_brk
    case TARGET_NR_brk: return 1;
#endif
#ifdef TARGET_NR_ioctl
    case TARGET_NR_ioctl: return 3;
#endif
#ifdef TARGET_NR_pread64
    case TARGET_NR_pread64: return 4;
#endif
#ifdef TARGET_NR_pwrite64
    case TARGET_NR_pwrite64: return 4;
#endif
#ifdef TARGET_NR_readv
    case TARGET_NR_readv: return 3;
#endif
#ifdef TARGET_NR_writev
    case TARGET_NR_writev: return 3;
#endif
#ifdef TARGET_NR_access
    case TARGET_NR_access: return 2;
#endif
#ifdef TARGET_NR_pipe
    case TARGET_NR_pipe: return 1;
#endif
#ifdef TARGET_NR_select
    case TARGET_NR_select: return 5;
#endif
#ifdef TARGET_NR_mremap
    case TARGET_NR_mremap: return 5;
#endif
#ifdef TARGET_NR_shmget
    case TARGET_NR_shmget: return 3;
#endif
#ifdef TARGET_NR_shmat
    case TARGET_NR_shmat: return 3;
#endif
#ifdef TARGET_NR_shmctl
    case TARGET_NR_shmctl: return 3;
#endif
#ifdef TARGET_NR_dup
    case TARGET_NR_dup: return 1;
#endif
#ifdef TARGET_NR_dup2
    case TARGET_NR_dup2: return 2;
#endif
#ifdef TARGET_NR_nanosleep
    case TARGET_NR_nanosleep: return 2;
#endif
#ifdef TARGET_NR_getitimer
    case TARGET_NR_getitimer: return 2;
#endif
#ifdef TARGET_NR_setitimer
    case TARGET_NR_setitimer: return 3;
#endif
#ifdef TARGET_NR_socket
    case TARGET_NR_socket: return 3;
#endif
#ifdef TARGET_NR_connect
    case TARGET_NR_connect: return 3;
#endif
#ifdef TARGET_NR_accept
    case TARGET_NR_accept: return 3;
#endif
#ifdef TARGET_NR_sendto
    case TARGET_NR_sendto: return 6;
#endif
#ifdef TARGET_NR_recvfrom
    case TARGET_NR_recvfrom: return 6;
#endif
#ifdef TARGET_NR_sendmsg
    case TARGET_NR_sendmsg: return 3;
#endif
#ifdef TARGET_NR_recvmsg
    case TARGET_NR_recvmsg: return 3;
#endif
#ifdef TARGET_NR_bind
    case TARGET_NR_bind: return 3;
#endif
#ifdef TARGET_NR_listen
    case TARGET_NR_listen: return 2;
#endif
#ifdef TARGET_NR_setsockopt
    case TARGET_NR_setsockopt: return 5;
#endif
#ifdef TARGET_NR_getsockopt
    case TARGET_NR_getsockopt: return 5;
#endif
#ifdef TARGET_NR_clone
    case TARGET_NR_clone: return 5;
#endif
#ifdef TARGET_NR_execve
    case TARGET_NR_execve: return 3;
#endif
#ifdef TARGET_NR_exit
    case TARGET_NR_exit: return 1;
#endif
#ifdef TARGET_NR_wait4
    case TARGET_NR_wait4: return 4;
#endif
#ifdef TARGET_NR_kill
    case TARGET_NR_kill: return 2;
#endif
#ifdef TARGET_NR_uname
    case TARGET_NR_uname: return 1;
#endif
#ifdef TARGET_NR_fcntl
    case TARGET_NR_fcntl: return 3;
#endif
#ifdef TARGET_NR_getcwd
    case TARGET_NR_getcwd: return 2;
#endif
#ifdef TARGET_NR_chdir
    case TARGET_NR_chdir: return 1;
#endif
#ifdef TARGET_NR_rename
    case TARGET_NR_rename: return 2;
#endif
#ifdef TARGET_NR_mkdir
    case TARGET_NR_mkdir: return 2;
#endif
#ifdef TARGET_NR_unlink
    case TARGET_NR_unlink: return 1;
#endif
#ifdef TARGET_NR_readlink
    case TARGET_NR_readlink: return 3;
#endif
#ifdef TARGET_NR_gettimeofday
    case TARGET_NR_gettimeofday: return 2;
#endif
#ifdef TARGET_NR_getrlimit
    case TARGET_NR_getrlimit: return 2;
#endif
#ifdef TARGET_NR_getrusage
    case TARGET_NR_getrusage: return 2;
#endif
#ifdef TARGET_NR_time
    case TARGET_NR_time: return 1;
#endif
#ifdef TARGET_NR_futex
    case TARGET_NR_futex: return 6;
#endif
#ifdef TARGET_NR_set_tid_address
    case TARGET_NR_set_tid_address: return 1;
#endif
#ifdef TARGET_NR_set_robust_list
    case TARGET_NR_set_robust_list: return 2;
#endif
#ifdef TARGET_NR_clock_gettime
    case TARGET_NR_clock_gettime: return 2;
#endif
#ifdef TARGET_NR_clock_getres
    case TARGET_NR_clock_getres: return 2;
#endif
#ifdef TARGET_NR_exit_group
    case TARGET_NR_exit_group: return 1;
#endif
#ifdef TARGET_NR_openat
    case TARGET_NR_openat: return 4;
#endif
#ifdef TARGET_NR_newfstatat
    case TARGET_NR_newfstatat: return 4;
#endif
#ifdef TARGET_NR_readlinkat
    case TARGET_NR_readlinkat: return 4;
#endif
#ifdef TARGET_NR_pselect6
    case TARGET_NR_pselect6: return 6;
#endif
#ifdef TARGET_NR_ppoll
    case TARGET_NR_ppoll: return 5;
#endif
#ifdef TARGET_NR_prlimit64
    case TARGET_NR_prlimit64: return 4;
#endif
#ifdef TARGET_NR_getrandom
    case TARGET_NR_getrandom: return 3;
#endif
#ifdef TARGET_NR_statx
    case TARGET_NR_statx: return 5;
#endif
#ifdef TARGET_NR_getuid
    case TARGET_NR_getuid: return 0;
#endif
#ifdef TARGET_NR_getgid
    case TARGET_NR_getgid: return 0;
#endif
#ifdef TARGET_NR_getpid
    case TARGET_NR_getpid: return 0;
#endif
#ifdef TARGET_NR_gettid
    case TARGET_NR_gettid: return 0;
#endif
#ifdef TARGET_NR_setuid
    case TARGET_NR_setuid: return 1;
#endif
#ifdef TARGET_NR_setgid
    case TARGET_NR_setgid: return 1;
#endif
#ifdef TARGET_NR_arch_prctl
    case TARGET_NR_arch_prctl: return 2;
#endif
    default: return 0;
  }
}

/* --- CMP/SUB checkpoints.
 *
 * raw/strict mode records operands, matching LLVM DMSAN's default ICmp/FCmp
 * differential sensitivity.  Result mode cannot record a semantically exact
 * ICmp predicate at the CMP producer because x86 signedness/equality choice is
 * only known when a later jcc/setcc/cmov consumes EFLAGS.  In result mode,
 * leave CMP producers silent and let those concrete consumers record their
 * actual result. */

void HELPER(qdmsan_checkpoint_8)(target_ulong cur_loc,
                                  target_ulong arg1, target_ulong arg2) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint8_t a = (uint8_t)arg1, b = (uint8_t)arg2;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_cmp_raw((uint64_t)cur_loc, a, b, QDMSAN_EVENT_CMP, 1);
    return;
  }
}

void HELPER(qdmsan_checkpoint_16)(target_ulong cur_loc,
                                   target_ulong arg1, target_ulong arg2) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint16_t a = (uint16_t)arg1, b = (uint16_t)arg2;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_cmp_raw((uint64_t)cur_loc, a, b, QDMSAN_EVENT_CMP, 2);
    return;
  }
}

void HELPER(qdmsan_checkpoint_32)(target_ulong cur_loc,
                                   target_ulong arg1, target_ulong arg2) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint32_t a = (uint32_t)arg1, b = (uint32_t)arg2;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_cmp_raw((uint64_t)cur_loc, a, b, QDMSAN_EVENT_CMP, 4);
    return;
  }
}

void HELPER(qdmsan_checkpoint_64)(target_ulong cur_loc,
                                   target_ulong arg1, target_ulong arg2) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_cmp_raw((uint64_t)cur_loc, (uint64_t)arg1, (uint64_t)arg2,
                          QDMSAN_EVENT_CMP, 8);
    return;
  }
}

/* CMP with an immediate constant: LLVM DMSAN does not add constants to the
 * multi-checkpoint operand list.  In raw mode record only the dynamic operand;
 * result mode waits for the concrete flag consumer. */
void HELPER(qdmsan_checkpoint_imm_8)(target_ulong cur_loc,
                                      target_ulong arg, target_ulong imm) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint8_t a = (uint8_t)arg;
  (void)imm;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_event((uint64_t)cur_loc, a, QDMSAN_EVENT_CMP, 1);
    return;
  }
}

void HELPER(qdmsan_checkpoint_imm_16)(target_ulong cur_loc,
                                       target_ulong arg, target_ulong imm) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint16_t a = (uint16_t)arg;
  (void)imm;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_event((uint64_t)cur_loc, a, QDMSAN_EVENT_CMP, 2);
    return;
  }
}

void HELPER(qdmsan_checkpoint_imm_32)(target_ulong cur_loc,
                                       target_ulong arg, target_ulong imm) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint32_t a = (uint32_t)arg;
  (void)imm;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_event((uint64_t)cur_loc, a, QDMSAN_EVENT_CMP, 4);
    return;
  }
}

void HELPER(qdmsan_checkpoint_imm_64)(target_ulong cur_loc,
                                       target_ulong arg, target_ulong imm) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_event((uint64_t)cur_loc, (uint64_t)arg, QDMSAN_EVENT_CMP, 8);
    return;
  }
  (void)imm;
}

/* --- AND checkpoints: record TEST/AND use.
 * x TEST y / x AND y sets ZF=(result==0), SF=((signed)result<0).
 * raw/strict records operands for register/memory forms. For immediate-mask
 * forms, raw records only (arg & imm): masked-off bits are not consumed by the
 * TEST/AND decision and recording them creates QDMSAN-only noise. result
 * records ZF+SF of (a & b), so BUG only means the poison value changed the
 * consumed TEST/AND result.
 *
 * Filters:
 *  - absorbing (0): x AND 0 = 0 regardless of x (result independent of x)
 *  - BOGUS bitmask constants: compiler strlen/memchr idiom
 *
 * bit 0 = ZF (result == 0)
 * bit 1 = SF (result <s 0, i.e. MSB set)
 *
 * Skip when result is equal in both operands (a == b already handled by
 * ZF/SF being deterministic when both fills produce same bit pattern).    */

void HELPER(qdmsan_and_checkpoint_8)(target_ulong cur_loc,
                                      target_ulong arg1, target_ulong arg2) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint8_t a = (uint8_t)arg1, b = (uint8_t)arg2;
  if (a == 0 || b == 0) return;          /* absorbing */
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_cmp_raw((uint64_t)cur_loc, a, b, QDMSAN_EVENT_AND, 1);
    return;
  }
  uint8_t result = a & b;
  qdmsan_dump_entry((uint64_t)cur_loc, (uint64_t)a, (uint64_t)b);
  int zf = (result == 0);
  int sf = ((int8_t)result < 0);
  uint64_t value = (uint64_t)(zf | (sf << 1));
  qdmsan_record_cmp_outcome((uint64_t)cur_loc, value, QDMSAN_EVENT_AND, 1);
}

void HELPER(qdmsan_and_checkpoint_16)(target_ulong cur_loc,
                                       target_ulong arg1, target_ulong arg2) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint16_t a = (uint16_t)arg1, b = (uint16_t)arg2;
  if (a == 0 || b == 0) return;              /* absorbing */
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_cmp_raw((uint64_t)cur_loc, a, b, QDMSAN_EVENT_AND, 2);
    return;
  }
  uint16_t result = a & b;
  qdmsan_dump_entry((uint64_t)cur_loc, (uint64_t)a, (uint64_t)b);
  int zf = (result == 0);
  int sf = ((int16_t)result < 0);
  uint64_t value = (uint64_t)(zf | (sf << 1));
  qdmsan_record_cmp_outcome((uint64_t)cur_loc, value, QDMSAN_EVENT_AND, 2);
}

void HELPER(qdmsan_and_checkpoint_32)(target_ulong cur_loc,
                                       target_ulong arg1, target_ulong arg2) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint32_t a = (uint32_t)arg1, b = (uint32_t)arg2;
  if (a == 0 || b == 0) return;                  /* absorbing */
  if (QDMSAN_IS_BOGUS((uint64_t)a) || QDMSAN_IS_BOGUS((uint64_t)b)) return;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_cmp_raw((uint64_t)cur_loc, a, b, QDMSAN_EVENT_AND, 4);
    return;
  }
  uint32_t result = a & b;
  qdmsan_dump_entry((uint64_t)cur_loc, (uint64_t)a, (uint64_t)b);
  int zf = (result == 0);
  int sf = ((int32_t)result < 0);
  uint64_t value = (uint64_t)(zf | (sf << 1));
  qdmsan_record_cmp_outcome((uint64_t)cur_loc, value, QDMSAN_EVENT_AND, 4);
}

void HELPER(qdmsan_and_checkpoint_64)(target_ulong cur_loc,
                                       target_ulong arg1, target_ulong arg2) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  if (arg1 == 0 || arg2 == 0) return;                    /* absorbing */
  if (QDMSAN_IS_BOGUS((uint64_t)arg1) || QDMSAN_IS_BOGUS((uint64_t)arg2)) return;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_cmp_raw((uint64_t)cur_loc, (uint64_t)arg1, (uint64_t)arg2,
                          QDMSAN_EVENT_AND, 8);
    return;
  }
  uint64_t result = (uint64_t)arg1 & (uint64_t)arg2;
  qdmsan_dump_entry((uint64_t)cur_loc, (uint64_t)arg1, (uint64_t)arg2);
  int zf = (result == 0);
  int sf = ((int64_t)result < 0);
  uint64_t value = (uint64_t)(zf | (sf << 1));
  qdmsan_record_cmp_outcome((uint64_t)cur_loc, value, QDMSAN_EVENT_AND, 8);
}

void HELPER(qdmsan_and_checkpoint_imm_8)(target_ulong cur_loc,
                                          target_ulong arg, target_ulong imm) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint8_t a = (uint8_t)arg, b = (uint8_t)imm;
  if (b == 0) return;
  uint8_t result = a & b;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_event((uint64_t)cur_loc, result, QDMSAN_EVENT_AND, 1);
    return;
  }
  qdmsan_dump_entry((uint64_t)cur_loc, (uint64_t)a, (uint64_t)b);
  int zf = (result == 0);
  int sf = ((int8_t)result < 0);
  uint64_t value = (uint64_t)(zf | (sf << 1));
  qdmsan_record_cmp_outcome((uint64_t)cur_loc, value, QDMSAN_EVENT_AND, 1);
}

void HELPER(qdmsan_and_checkpoint_imm_16)(target_ulong cur_loc,
                                           target_ulong arg, target_ulong imm) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint16_t a = (uint16_t)arg, b = (uint16_t)imm;
  if (b == 0) return;
  uint16_t result = a & b;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_event((uint64_t)cur_loc, result, QDMSAN_EVENT_AND, 2);
    return;
  }
  qdmsan_dump_entry((uint64_t)cur_loc, (uint64_t)a, (uint64_t)b);
  int zf = (result == 0);
  int sf = ((int16_t)result < 0);
  uint64_t value = (uint64_t)(zf | (sf << 1));
  qdmsan_record_cmp_outcome((uint64_t)cur_loc, value, QDMSAN_EVENT_AND, 2);
}

void HELPER(qdmsan_and_checkpoint_imm_32)(target_ulong cur_loc,
                                           target_ulong arg, target_ulong imm) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint32_t a = (uint32_t)arg, b = (uint32_t)imm;
  if (b == 0) return;
  if (QDMSAN_IS_BOGUS((uint64_t)a) || QDMSAN_IS_BOGUS((uint64_t)b)) return;
  uint32_t result = a & b;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_event((uint64_t)cur_loc, result, QDMSAN_EVENT_AND, 4);
    return;
  }
  qdmsan_dump_entry((uint64_t)cur_loc, (uint64_t)a, (uint64_t)b);
  int zf = (result == 0);
  int sf = ((int32_t)result < 0);
  uint64_t value = (uint64_t)(zf | (sf << 1));
  qdmsan_record_cmp_outcome((uint64_t)cur_loc, value, QDMSAN_EVENT_AND, 4);
}

void HELPER(qdmsan_and_checkpoint_imm_64)(target_ulong cur_loc,
                                           target_ulong arg, target_ulong imm) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  if (imm == 0) return;
  if (QDMSAN_IS_BOGUS((uint64_t)arg) || QDMSAN_IS_BOGUS((uint64_t)imm)) return;
  uint64_t result = (uint64_t)arg & (uint64_t)imm;
  if (qdmsan_check_mode == QDMSAN_CHECK_RAW) {
    qdmsan_record_event((uint64_t)cur_loc, result, QDMSAN_EVENT_AND, 8);
    return;
  }
  qdmsan_dump_entry((uint64_t)cur_loc, (uint64_t)arg, (uint64_t)imm);
  int zf = (result == 0);
  int sf = ((int64_t)result < 0);
  uint64_t value = (uint64_t)(zf | (sf << 1));
  qdmsan_record_cmp_outcome((uint64_t)cur_loc, value, QDMSAN_EVENT_AND, 8);
}

/* --- SSE/AVX floating-point compare checkpoint --- */

/* ucomiss / ucomisd / comiss / comisd all store their result in env->cc_src
 * as one of four EFLAGS values (CC_C, CC_Z, 0, CC_Z|CC_P|CC_C) and set
 * CC_OP = CC_OP_EFLAGS.  Recording this value detects when uninitialized
 * float data causes different comparison outcomes between runs. */
void HELPER(qdmsan_ucomis_checkpoint)(target_ulong cur_loc, CPUArchState *env) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  uint64_t value = (uint64_t)(uint32_t)env->cc_src;
  qdmsan_record_event((uint64_t)cur_loc, value, QDMSAN_EVENT_FCMP, 4);
}

void HELPER(qdmsan_value_checkpoint)(target_ulong cur_loc, target_ulong value,
                                     target_ulong kind) {
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  qdmsan_record_event((uint64_t)cur_loc, (uint64_t)value, (uint32_t)kind,
                      sizeof(target_ulong));
}

void HELPER(qdmsan_ptr_checkpoint)(target_ulong cur_loc, target_ulong value,
                                   target_ulong kind) {
  if (!qdmsan_pointer_checks_enabled) return;
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();
  qdmsan_record_event((uint64_t)cur_loc, (uint64_t)value, (uint32_t)kind,
                      sizeof(target_ulong));
}

/* --- Stack frame poisoning --- */

/* Stack-probe guard: GCC emits  sub $0x1000,%rsp; orq $0,(%rsp)  for every
 * page when the frame exceeds the page size.  That page-sized SUB triggers
 * qdmsan_stack_alloc with sz == PAGE_SIZE.  Poisoning it makes the probe
 * OR read poison → false positive.  Using '>=' skips the exact page-size
 * decrement (the probe) while still filling normal frames < page-size.    */
#define QDMSAN_STACK_PAGE 4096u

void HELPER(qdmsan_stack_alloc)(target_ulong new_sp, target_ulong old_sp) {
  if (!qdmsan_stack_poison_enabled) return;
  if (!qdmsan_main_started) return;
  if (!__qdmsan_qemu_poison) return;
  if (new_sp >= old_sp) return;                    /* RSP not decreasing */
  size_t sz = (size_t)(old_sp - new_sp);
  /* Default qdmsan_stack_max_fill == QDMSAN_STACK_PAGE (4096): skip the page
   * probe and over-large frames.  AFL_QDMSAN_STACK_MAX raises this bound. */
  if (sz >= qdmsan_stack_max_fill) return;         /* skip probe & over-large */
  if (!thread_cpu || !access_ok(thread_cpu, VERIFY_WRITE, new_sp, sz)) return;
  qdmsan_fill_host_for_guest(AFL_G2H(new_sp), new_sp, sz,
                             qdmsan_current_poison());
}

/* x86-64 red zone: 128 bytes below RSP used by leaf functions without SUB RSP.
 * Called at CALL time (before push of return address), so:
 *   callee_rsp  = caller_rsp - 8   (after push)
 *   red_zone    = [callee_rsp - 128, callee_rsp)
 *               = [caller_rsp - 136, caller_rsp - 8)                         */
void HELPER(qdmsan_call_fill)(target_ulong caller_rsp) {
  if (!qdmsan_stack_poison_enabled) return;
  if (!qdmsan_main_started) return;
  if (!__qdmsan_qemu_poison) return;
  target_ulong red_start = caller_rsp - 8 - 128;
  if (!thread_cpu || !access_ok(thread_cpu, VERIFY_WRITE, red_start, 128)) return;
  qdmsan_fill_host_for_guest(AFL_G2H(red_start), red_start, 128,
                             qdmsan_current_poison());
}

static void qdmsan_record_syscall_locked(int num, target_ulong arg1,
                                        target_ulong arg2, target_ulong arg3,
                                        target_ulong arg4, target_ulong arg5,
                                        target_ulong arg6) {
  if (!qdmsan_syscall_checks_enabled) return;
  if (num == QDMSAN_FAKESYS_NR) return;
  if (!qdmsan_has_recording_map()) return;
  QDMSAN_MAIN_FILTER();

  uint64_t pc = QDMSAN_SYSCALL_PC_NS | (uint32_t)num;
  int arity = qdmsan_syscall_arity(num);
  uint64_t args[6];
  unsigned arg_count = 0;
  if (arity >= 1) {
    args[arg_count++] = qdmsan_stable_syscall_arg(num, 1, arg1);
  }
  if (arity >= 2) {
    args[arg_count++] = qdmsan_stable_syscall_arg(num, 2, arg2);
  }
  if (arity >= 3) {
    args[arg_count++] = qdmsan_stable_syscall_arg(num, 3, arg3);
  }
  if (arity >= 4) {
    args[arg_count++] = qdmsan_stable_syscall_arg(num, 4, arg4);
  }
  if (arity >= 5) {
    args[arg_count++] = qdmsan_stable_syscall_arg(num, 5, arg5);
  }
  if (arity >= 6) {
    args[arg_count++] = qdmsan_stable_syscall_arg(num, 6, arg6);
  }
  if (arg_count) {
    qdmsan_record_event(pc, qdmsan_combine_values(args, arg_count),
                        QDMSAN_EVENT_SYSCALL | 0x100u, 8);
  }

  switch (num) {
#ifdef TARGET_NR_write
    case TARGET_NR_write:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg2, arg3),
                          QDMSAN_EVENT_SYSCALL | 0x700u, 8);
      break;
#endif
#ifdef TARGET_NR_pwrite64
    case TARGET_NR_pwrite64:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg2, arg3),
                          QDMSAN_EVENT_SYSCALL | 0x701u, 8);
      break;
#endif
#ifdef TARGET_NR_writev
    case TARGET_NR_writev:
      qdmsan_record_event(pc, qdmsan_hash_guest_iovec(arg2, arg3),
                          QDMSAN_EVENT_SYSCALL | 0x702u, 8);
      break;
#endif
#ifdef TARGET_NR_pwritev
    case TARGET_NR_pwritev:
      qdmsan_record_event(pc, qdmsan_hash_guest_iovec(arg2, arg3),
                          QDMSAN_EVENT_SYSCALL | 0x703u, 8);
      break;
#endif
#ifdef TARGET_NR_pwritev2
    case TARGET_NR_pwritev2:
      qdmsan_record_event(pc, qdmsan_hash_guest_iovec(arg2, arg3),
                          QDMSAN_EVENT_SYSCALL | 0x704u, 8);
      break;
#endif
#ifdef TARGET_NR_sendto
    case TARGET_NR_sendto:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg2, arg3),
                          QDMSAN_EVENT_SYSCALL | 0x705u, 8);
      break;
#endif
#ifdef TARGET_NR_sendmsg
    case TARGET_NR_sendmsg:
      qdmsan_record_event(pc, qdmsan_hash_guest_msghdr_iov(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x706u, 8);
      break;
#endif
#ifdef TARGET_NR_sendmmsg
    case TARGET_NR_sendmmsg:
      if (arg2 && arg3 && thread_cpu &&
          access_ok(thread_cpu, VERIFY_READ, arg2,
                    sizeof(struct target_mmsghdr))) {
        const struct target_mmsghdr *mmsg = AFL_G2H(arg2);
        qdmsan_record_event(
            pc, qdmsan_hash_guest_iovec(
                    (target_ulong)tswapal(mmsg->msg_hdr.msg_iov),
                    (target_ulong)tswapal(mmsg->msg_hdr.msg_iovlen)),
            QDMSAN_EVENT_SYSCALL | 0x707u, 8);
      }
      break;
#endif
#ifdef TARGET_NR_open
    case TARGET_NR_open:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x720u, 8);
      break;
#endif
#ifdef TARGET_NR_openat
    case TARGET_NR_openat:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x721u, 8);
      break;
#endif
#ifdef TARGET_NR_stat
    case TARGET_NR_stat:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x722u, 8);
      break;
#endif
#ifdef TARGET_NR_stat64
    case TARGET_NR_stat64:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x723u, 8);
      break;
#endif
#ifdef TARGET_NR_lstat
    case TARGET_NR_lstat:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x724u, 8);
      break;
#endif
#ifdef TARGET_NR_lstat64
    case TARGET_NR_lstat64:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x725u, 8);
      break;
#endif
#ifdef TARGET_NR_newfstatat
    case TARGET_NR_newfstatat:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x726u, 8);
      break;
#endif
#ifdef TARGET_NR_fstatat64
    case TARGET_NR_fstatat64:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x727u, 8);
      break;
#endif
#ifdef TARGET_NR_statx
    case TARGET_NR_statx:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x728u, 8);
      break;
#endif
#ifdef TARGET_NR_readlink
    case TARGET_NR_readlink:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x729u, 8);
      break;
#endif
#ifdef TARGET_NR_readlinkat
    case TARGET_NR_readlinkat:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x72au, 8);
      break;
#endif
#ifdef TARGET_NR_name_to_handle_at
    case TARGET_NR_name_to_handle_at:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x72bu, 8);
      break;
#endif
#ifdef TARGET_NR_getxattr
    case TARGET_NR_getxattr:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x72cu, 8);
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x72du, 8);
      break;
#endif
#ifdef TARGET_NR_lgetxattr
    case TARGET_NR_lgetxattr:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x72eu, 8);
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x72fu, 8);
      break;
#endif
#ifdef TARGET_NR_fgetxattr
    case TARGET_NR_fgetxattr:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg2),
                          QDMSAN_EVENT_SYSCALL | 0x730u, 8);
      break;
#endif
#ifdef TARGET_NR_listxattr
    case TARGET_NR_listxattr:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x731u, 8);
      break;
#endif
#ifdef TARGET_NR_llistxattr
    case TARGET_NR_llistxattr:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x732u, 8);
      break;
#endif
#ifdef TARGET_NR_statfs
    case TARGET_NR_statfs:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x733u, 8);
      break;
#endif
#ifdef TARGET_NR_statfs64
    case TARGET_NR_statfs64:
      qdmsan_record_event(pc, qdmsan_hash_guest_cstr(arg1),
                          QDMSAN_EVENT_SYSCALL | 0x734u, 8);
      break;
#endif
#ifdef TARGET_NR_accept
    case TARGET_NR_accept:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg3, 8),
                          QDMSAN_EVENT_SYSCALL | 0x740u, 8);
      break;
#endif
#ifdef TARGET_NR_accept4
    case TARGET_NR_accept4:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg3, 8),
                          QDMSAN_EVENT_SYSCALL | 0x741u, 8);
      break;
#endif
#ifdef TARGET_NR_getsockname
    case TARGET_NR_getsockname:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg3, 8),
                          QDMSAN_EVENT_SYSCALL | 0x742u, 8);
      break;
#endif
#ifdef TARGET_NR_getpeername
    case TARGET_NR_getpeername:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg3, 8),
                          QDMSAN_EVENT_SYSCALL | 0x743u, 8);
      break;
#endif
#ifdef TARGET_NR_getsockopt
    case TARGET_NR_getsockopt:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg5, 8),
                          QDMSAN_EVENT_SYSCALL | 0x744u, 8);
      break;
#endif
#ifdef TARGET_NR_poll
    case TARGET_NR_poll:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg1, arg2 * 8),
                          QDMSAN_EVENT_SYSCALL | 0x745u, 8);
      break;
#endif
#ifdef TARGET_NR_ppoll
    case TARGET_NR_ppoll:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg1, arg2 * 8),
                          QDMSAN_EVENT_SYSCALL | 0x746u, 8);
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg3, 32),
                          QDMSAN_EVENT_SYSCALL | 0x747u, 8);
      break;
#endif
#ifdef TARGET_NR_setitimer
    case TARGET_NR_setitimer:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg2, 64),
                          QDMSAN_EVENT_SYSCALL | 0x748u, 8);
      break;
#endif
#ifdef TARGET_NR_timerfd_settime
    case TARGET_NR_timerfd_settime:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg3, 64),
                          QDMSAN_EVENT_SYSCALL | 0x749u, 8);
      break;
#endif
#ifdef TARGET_NR_rt_sigtimedwait
    case TARGET_NR_rt_sigtimedwait:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg1, arg4),
                          QDMSAN_EVENT_SYSCALL | 0x74au, 8);
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg3, 32),
                          QDMSAN_EVENT_SYSCALL | 0x74bu, 8);
      break;
#endif
#ifdef TARGET_NR_msgsnd
    case TARGET_NR_msgsnd:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg2, arg3 + 16),
                          QDMSAN_EVENT_SYSCALL | 0x74cu, 8);
      break;
#endif
#ifdef TARGET_NR_recvmmsg
    case TARGET_NR_recvmmsg:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg5, 32),
                          QDMSAN_EVENT_SYSCALL | 0x74du, 8);
      break;
#endif
#ifdef TARGET_NR_prlimit64
    case TARGET_NR_prlimit64:
      if (arg3 && qdmsan_prlimit64_reads_new_limit(arg2)) {
        qdmsan_record_event(pc,
                            qdmsan_hash_guest_bytes(
                                arg3, QDMSAN_TARGET_RLIMIT64_SIZE),
                            QDMSAN_EVENT_SYSCALL | 0x74eu, 8);
      }
      break;
#endif
#ifdef TARGET_NR_process_vm_writev
    case TARGET_NR_process_vm_writev:
      qdmsan_record_event(pc, qdmsan_hash_guest_iovec(arg2, arg3),
                          QDMSAN_EVENT_SYSCALL | 0x74fu, 8);
      break;
#endif
#ifdef TARGET_NR_open_by_handle_at
    case TARGET_NR_open_by_handle_at:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg2, 64),
                          QDMSAN_EVENT_SYSCALL | 0x750u, 8);
      break;
#endif
#ifdef TARGET_NR_capset
    case TARGET_NR_capset:
      qdmsan_record_event(pc, qdmsan_hash_guest_bytes(arg2, 64),
                          QDMSAN_EVENT_SYSCALL | 0x751u, 8);
      break;
#endif
    default:
      break;
  }
}

void qdmsan_record_syscall(int num, target_ulong arg1, target_ulong arg2,
                           target_ulong arg3, target_ulong arg4,
                           target_ulong arg5, target_ulong arg6) {
  if (!qdmsan_syscall_checks_enabled || num == QDMSAN_FAKESYS_NR ||
      !qdmsan_has_recording_map()) return;
  qdmsan_mark_thread_for_flush();
  pthread_mutex_lock(&qdmsan_threads_lock);
  if (!qdmsan_process_exiting) {
    qdmsan_record_syscall_locked(num, arg1, arg2, arg3, arg4, arg5, arg6);
  }
  pthread_mutex_unlock(&qdmsan_threads_lock);
}

target_ulong qdmsan_actions_dispatcher(target_ulong action, target_ulong arg1,
                                        target_ulong arg2, target_ulong arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;

  switch (action) {
    case QDMSAN_ACTION_PREMAIN:
      qdmsan_main_started = 0;
      return 0;
    case QDMSAN_ACTION_MAIN_STARTED:
      qdmsan_main_started = 1;
      return 0;
    case QDMSAN_ACTION_POISON:
      if (!__qdmsan_qemu_poison || !arg1 || !arg2) return 0;
      if (!thread_cpu ||
          !access_ok(thread_cpu, VERIFY_WRITE, (target_ulong)arg1,
                     (size_t)arg2)) {
        return (target_ulong)-TARGET_EFAULT;
      }
      qdmsan_fill_host_for_guest(AFL_G2H((target_ulong)arg1),
                                 (target_ulong)arg1, (size_t)arg2,
                                 qdmsan_current_poison());
      return 0;
    case QDMSAN_ACTION_SUPPRESS_ENTER:
      ++qdmsan_recording_suppressed;
      return 0;
    case QDMSAN_ACTION_SUPPRESS_LEAVE:
      if (qdmsan_recording_suppressed > 0) {
        --qdmsan_recording_suppressed;
      }
      return 0;
    case QDMSAN_ACTION_RECORD:
      qdmsan_mark_thread_for_flush();
      pthread_mutex_lock(&qdmsan_threads_lock);
      if (!qdmsan_process_exiting) {
        qdmsan_record_event_filtered((uint64_t)arg1, (uint64_t)arg2,
                                   QDMSAN_EVENT_LIBC |
                                       (((uint32_t)arg3 & 0xffffu) << 8),
                                   sizeof(target_ulong));
      }
      pthread_mutex_unlock(&qdmsan_threads_lock);
      return 0;
    case QDMSAN_ACTION_FIXED_RAND_RAW:
      if (!arg1 || arg2 < sizeof(uint64_t) || !thread_cpu ||
          !access_ok(thread_cpu, VERIFY_WRITE, (target_ulong)arg1,
                     sizeof(uint64_t))) {
        return (target_ulong)-TARGET_EFAULT;
      }
      {
        uint64_t x = qdmsan_fixed_rand_raw_next();
        memcpy(AFL_G2H((target_ulong)arg1), &x, sizeof(x));
      }
      return 0;
    case QDMSAN_ACTION_FIXED_RAND_BYTES:
      if (arg2 && (!arg1 || !thread_cpu ||
                   !access_ok(thread_cpu, VERIFY_WRITE, (target_ulong)arg1,
                              (size_t)arg2))) {
        return (target_ulong)-TARGET_EFAULT;
      }
      if (arg2) {
        qdmsan_fill_fixed_rand_bytes(AFL_G2H((target_ulong)arg1),
                                     (size_t)arg2);
      }
      return 0;
    case QDMSAN_ACTION_FIXED_TIME_SEC:
      return (target_ulong)qdmsan_fixed_time_sec_next();
    case QDMSAN_ACTION_FIXED_TIME_USEC:
      return (target_ulong)(__qdmsan_qemu_map
                                ? __qdmsan_qemu_map->fixed_time_usec
                                : 0);
    case QDMSAN_ACTION_REGION_ADD: {
      /* Accept and ignore: returning an error here would leak errno=ENOSYS
       * into the guest through libqdmsan's nested free path. */
      if (!qdmsan_heap_planes_enabled) return 0;
      int rc = qdmsan_region_add(arg1, arg2, arg3);
      if (!rc && __qdmsan_qemu_map) {
        atomic_fetch_or(
            (_Atomic uint64_t *)&__qdmsan_qemu_map
                ->padding[QDMSAN_FLAGS_LANE],
            QDMSAN_ACCESS_ABI_VERSION | QDMSAN_ACCESS_FLAG_REGISTRY |
                QDMSAN_ACCESS_FLAG_PRESTORE);
      }
      return (target_ulong)rc;
    }
    case QDMSAN_ACTION_REGION_REMOVE:
      /* Accept and ignore: returning an error here would leak errno=ENOSYS
       * into the guest through libqdmsan's nested free path. */
      if (!qdmsan_heap_planes_enabled) return 0;
      return (target_ulong)qdmsan_region_remove(arg1, arg2, arg3);
    default:
      return (target_ulong)-TARGET_ENOSYS;
  }
}

/////////////////////////////////////////////////
//                   QASAN
/////////////////////////////////////////////////

#include "qemuafl/qasan-qemu.h"

// options
int qasan_max_call_stack = 16; // QASAN_MAX_CALL_STACK
int qasan_symbolize = 1; // QASAN_SYMBOLIZE
int use_qasan = 0;

__thread int qasan_disabled;

__thread struct shadow_stack qasan_shadow_stack;

#ifdef ASAN_GIOVESE

#ifndef DO_NOT_USE_QASAN

#include "qemuafl/asan-giovese-inl.h"

#include <sys/types.h>
#include <sys/syscall.h>

void asan_giovese_populate_context(struct call_context* ctx, target_ulong pc) {

  ctx->size = MIN(qasan_shadow_stack.size, qasan_max_call_stack -1) +1;
  ctx->addresses = calloc(sizeof(void*), ctx->size);
  
#ifdef __NR_gettid
  ctx->tid = (uint32_t)syscall(__NR_gettid);
#else
  pthread_id_np_t tid;
  pthread_t self = pthread_self();
  pthread_getunique_np(&self, &tid);
  ctx->tid = (uint32_t)tid;
#endif

  ctx->addresses[0] = pc;
  
  if (qasan_shadow_stack.size <= 0) return; //can be negative when pop does not find nothing
  
  int i, j = 1;
  for (i = qasan_shadow_stack.first->index -1; i >= 0 && j < qasan_max_call_stack; --i)
    ctx->addresses[j++] = qasan_shadow_stack.first->buf[i];

  struct shadow_stack_block* b = qasan_shadow_stack.first->next;
  while (b && j < qasan_max_call_stack) {
  
    for (i = SHADOW_BK_SIZE-1; i >= 0; --i)
      ctx->addresses[j++] = b->buf[i];
  
  }

}

static void addr2line_cmd(char* lib, uintptr_t off, char** function, char** line) {
  
  if (!qasan_symbolize) goto addr2line_cmd_skip;
  
  FILE *fp;

  size_t cmd_siz = 128 + strlen(lib);
  char* cmd = malloc(cmd_siz);
  snprintf(cmd, cmd_siz, "addr2line -f -e '%s' 0x%lx", lib, off);

  fp = popen(cmd, "r");
  free(cmd);
  
  if (fp == NULL) goto addr2line_cmd_skip;

  *function = malloc(PATH_MAX + 32);
  
  if (!fgets(*function, PATH_MAX + 32, fp) || !strncmp(*function, "??", 2)) {

    free(*function);
    *function = NULL;

  } else {

    size_t l = strlen(*function);
    if (l && (*function)[l-1] == '\n')
      (*function)[l-1] = 0;
      
  }
  
  *line = malloc(PATH_MAX + 32);
  
  if (!fgets(*line, PATH_MAX + 32, fp) || !strncmp(*line, "??:", 3) ||
      !strncmp(*line, ":?", 2)) {

    free(*line);
    *line = NULL;

  } else {

    size_t l = strlen(*line);
    if (l && (*line)[l-1] == '\n')
      (*line)[l-1] = 0;
      
  }
  
  pclose(fp);
  
  return;

addr2line_cmd_skip:
  *line = NULL;
  *function = NULL;
  
}

char* asan_giovese_printaddr(target_ulong guest_addr) {

  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen("/proc/self/maps", "r");
  if (fp == NULL)
      return NULL;
  
  uint64_t img_min = 0; //, img_max = 0;
  char img_path[512] = {0};

  while ((read = getline(&line, &len, fp)) != -1) {
  
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line, "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d"
                    " %512s", &min, &max, &flag_r, &flag_w, &flag_x,
                    &flag_p, &offset, &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11))
        continue;

    if (h2g_valid(min)) {

      int flags = page_get_flags(h2g(min));
      max = h2g_valid(max - 1) ? max : (uintptr_t)AFL_G2H(GUEST_ADDR_MAX) + 1;
      if (page_check_range(h2g(min), max - min, flags) == -1)
          continue;
      
      if (img_min && !strcmp(img_path, path)) {
        //img_max = max;
      } else {
        img_min = min;
        //img_max = max;
        strncpy(img_path, path, 512);
      }

      if (guest_addr >= h2g(min) && guest_addr < h2g(max - 1) + 1) {
      
        uintptr_t off = guest_addr - h2g(img_min);
      
        char* s;
        char * function = NULL;
        char * codeline = NULL;
        if (strlen(path)) {
          addr2line_cmd(path, off, &function, &codeline);
          if (!function)
            addr2line_cmd(path, guest_addr, &function, &codeline);
        }

        if (function) {
        
          if (codeline) {
          
            size_t l = strlen(function) + strlen(codeline) + 32;
            s = malloc(l);
            snprintf(s, l, " in %s %s", function, codeline);
            free(codeline);
            
          } else {

            size_t l = strlen(function) + strlen(path) + 32;
            s = malloc(l);
            snprintf(s, l, " in %s (%s+0x%lx)", function, path,
                     off);

          }
          
          free(function);
        
        } else {

          size_t l = strlen(path) + 32;
          s = malloc(l);
          snprintf(s, l, " (%s+0x%lx)", path, off);

        }

        free(line);
        fclose(fp);
        return s;
        
      }

    }

  }

  free(line);
  fclose(fp);

  return NULL;

}

#endif

void HELPER(qasan_shadow_stack_push)(target_ulong ptr) {

#ifndef DO_NOT_USE_QASAN
#if defined(TARGET_ARM)
  ptr &= ~1;
#endif

  if (unlikely(!qasan_shadow_stack.first)) {
    
    qasan_shadow_stack.first = malloc(sizeof(struct shadow_stack_block));
    qasan_shadow_stack.first->index = 0;
    qasan_shadow_stack.size = 0; // may be negative due to last pop
    qasan_shadow_stack.first->next = NULL;

  }
    
  qasan_shadow_stack.first->buf[qasan_shadow_stack.first->index++] = ptr;
  qasan_shadow_stack.size++;

  if (qasan_shadow_stack.first->index >= SHADOW_BK_SIZE) {

      struct shadow_stack_block* ns = malloc(sizeof(struct shadow_stack_block));
      ns->next = qasan_shadow_stack.first;
      ns->index = 0;
      qasan_shadow_stack.first = ns;
  }
#endif

}

void HELPER(qasan_shadow_stack_pop)(target_ulong ptr) {

#ifndef DO_NOT_USE_QASAN
#if defined(TARGET_ARM)
  ptr &= ~1;
#endif

  struct shadow_stack_block* cur_bk = qasan_shadow_stack.first;
  if (unlikely(cur_bk == NULL)) return;

  do {
      
      cur_bk->index--;
      qasan_shadow_stack.size--;
      
      if (cur_bk->index < 0) {
          
          struct shadow_stack_block* ns = cur_bk->next;
          free(cur_bk);
          cur_bk = ns;
          if (!cur_bk) break;
          cur_bk->index--;
      }
      
  } while(cur_bk->buf[cur_bk->index] != ptr);
  
  qasan_shadow_stack.first = cur_bk;
#endif

}

#endif

target_long qasan_actions_dispatcher(void *cpu_env,
                                     target_long action, target_long arg1,
                                     target_long arg2, target_long arg3) {

#ifndef DO_NOT_USE_QASAN
    CPUArchState *env = cpu_env;

    switch(action) {
#ifdef ASAN_GIOVESE
        case QASAN_ACTION_CHECK_LOAD:
        if (asan_giovese_guest_loadN(arg1, arg2)) {
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, arg1, arg2, env);
        }
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        if (asan_giovese_guest_storeN(arg1, arg2)) {
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, arg1, arg2, env);
        }
        break;
        
        case QASAN_ACTION_POISON:
        asan_giovese_poison_guest_region(arg1, arg2, arg3);
        break;
        
        case QASAN_ACTION_USER_POISON:
        asan_giovese_user_poison_guest_region(arg1, arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        asan_giovese_unpoison_guest_region(arg1, arg2);
        break;
        
        case QASAN_ACTION_IS_POISON:
        return asan_giovese_guest_loadN(arg1, arg2);
        
        case QASAN_ACTION_ALLOC: {
          struct call_context* ctx = calloc(sizeof(struct call_context), 1);
          asan_giovese_populate_context(ctx, PC_GET(env));
          asan_giovese_alloc_insert(arg1, arg2, ctx);
          break;
        }
        
        case QASAN_ACTION_DEALLOC: {
          struct chunk_info* ckinfo = asan_giovese_alloc_search(arg1);
          if (ckinfo) {
            if (ckinfo->start != arg1)
              asan_giovese_badfree(arg1, PC_GET(env));
            ckinfo->free_ctx = calloc(sizeof(struct call_context), 1);
            asan_giovese_populate_context(ckinfo->free_ctx, PC_GET(env));
          } else {
            asan_giovese_badfree(arg1, PC_GET(env));
          }
          break;
        }
#else
        case QASAN_ACTION_CHECK_LOAD:
        __asan_loadN(AFL_G2H(arg1), arg2);
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        __asan_storeN(AFL_G2H(arg1), arg2);
        break;
        
        case QASAN_ACTION_POISON:
        __asan_poison_memory_region(AFL_G2H(arg1), arg2);
        break;
        
        case QASAN_ACTION_USER_POISON:
        __asan_poison_memory_region(AFL_G2H(arg1), arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        __asan_unpoison_memory_region(AFL_G2H(arg1), arg2);
        break;
        
        case QASAN_ACTION_IS_POISON:
        return __asan_region_is_poisoned(AFL_G2H(arg1), arg2) != NULL;
        
        case QASAN_ACTION_ALLOC:
          break;
        
        case QASAN_ACTION_DEALLOC:
          break;
#endif

        case QASAN_ACTION_ENABLE:
        qasan_disabled = 0;
        break;
        
        case QASAN_ACTION_DISABLE:
        qasan_disabled = 1;
        break;

        case QASAN_ACTION_SWAP_STATE: {
          int r = qasan_disabled;
          qasan_disabled = arg1;
          return r;
        }

        default:
        fprintf(stderr, "Invalid QASAN action " TARGET_FMT_ld "\n", action);
        abort();
    }
#endif

    return 0;
}

dh_ctype(tl) HELPER(qasan_fake_instr)(CPUArchState *env, dh_ctype(tl) action,
                                      dh_ctype(tl) arg1, dh_ctype(tl) arg2,
                                      dh_ctype(tl) arg3) {

  return qasan_actions_dispatcher(env, action, arg1, arg2, arg3);

}

void HELPER(qasan_load1)(CPUArchState *env, target_ulong addr) {

#ifndef DO_NOT_USE_QASAN
  if (qasan_disabled) return;
  
  void* ptr = (void*)AFL_G2H(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_load1(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 1, env);
  }
#else
  __asan_load1(ptr);
#endif
#endif

}

void HELPER(qasan_load2)(CPUArchState *env, target_ulong addr) {

#ifndef DO_NOT_USE_QASAN
  if (qasan_disabled) return;

  void* ptr = (void*)AFL_G2H(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_load2(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 2, env);
  }
#else
  __asan_load2(ptr);
#endif
#endif

}

void HELPER(qasan_load4)(CPUArchState *env, target_ulong addr) {

#ifndef DO_NOT_USE_QASAN
  if (qasan_disabled) return;
  
  void* ptr = (void*)AFL_G2H(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_load4(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 4, env);
  }
#else
  __asan_load4(ptr);
#endif
#endif

}

void HELPER(qasan_load8)(CPUArchState *env, target_ulong addr) {

#ifndef DO_NOT_USE_QASAN
  if (qasan_disabled) return;
  
  void* ptr = (void*)AFL_G2H(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_load8(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 8, env);
  }
#else
  __asan_load8(ptr);
#endif
#endif

}

void HELPER(qasan_store1)(CPUArchState *env, target_ulong addr) {

#ifndef DO_NOT_USE_QASAN
  if (qasan_disabled) return;
  
  void* ptr = (void*)AFL_G2H(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_store1(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 1, env);
  }
#else
  __asan_store1(ptr);
#endif
#endif

}

void HELPER(qasan_store2)(CPUArchState *env, target_ulong addr) {

#ifndef DO_NOT_USE_QASAN
  if (qasan_disabled) return;
  
  void* ptr = (void*)AFL_G2H(addr);
  
#ifdef ASAN_GIOVESE
  if (asan_giovese_store2(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 2, env);
  }
#else
  __asan_store2(ptr);
#endif
#endif

}

void HELPER(qasan_store4)(CPUArchState *env, target_ulong addr) {

#ifndef DO_NOT_USE_QASAN
  if (qasan_disabled) return;
  
  void* ptr = (void*)AFL_G2H(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_store4(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 4, env);
  }
#else
  __asan_store4(ptr);
#endif
#endif

}

void HELPER(qasan_store8)(CPUArchState *env, target_ulong addr) {

#ifndef DO_NOT_USE_QASAN
  if (qasan_disabled) return;

  void* ptr = (void*)AFL_G2H(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_store8(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 8, env);
  }
#else
  __asan_store8(ptr);
#endif
#endif

}
