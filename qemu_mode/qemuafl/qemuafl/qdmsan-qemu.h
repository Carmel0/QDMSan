/*
 * qdmsan-qemu.h - QDMSAN TCG checkpoint support (QEMU host side)
 *
 * QDMSAN reuses the AFL++/LLVM DMSAN shared-memory ABI. QEMU records dangerous
 * binary-level use points into the DMSAN fast map and optionally into the aux
 * feedback / full hash maps. QDMSAN's OOB/UAF result digests use reserved
 * fast-map lanes; mutable runtime control state stays outside the map.
 *
 * Enabled by: AFL_USE_QDMSAN=1 environment variable.
 */

#ifndef QDMSAN_QEMU_H
#define QDMSAN_QEMU_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/shm.h>

#include "common.h"

#define QDMSAN_SHADOW_BK_SIZE (4096 * 8)

/* ------------------------------------------------------------------ */
/* fast_map layout: must match include/dmsanfuzz.h and LLVM dmsan_map_fast.h. */
/* ------------------------------------------------------------------ */

struct qdmsan_qemu_fast_map {
  uint64_t sum_signature;
  uint64_t rotl_signature;
  uint64_t multiply_signature;
  uint64_t total_count;

  uint64_t fixed_time_sec;
  uint64_t fixed_time_usec;
  uint64_t fixed_rand_base;
  uint64_t fixed_tsc_base;

  uint64_t fixed_rdrand_base;
  uint64_t padding[7];
} __attribute__((aligned(64)));

/* QDMSAN-specific lanes reuse the reserved tail of the 128-byte fast map.
 * The UUM digest stays in the three legacy fields above; OOB and UAF are
 * access digests populated by the sparse region registry in tcg-runtime.c. */
#define QDMSAN_OOB_SUM_LANE   0u
#define QDMSAN_OOB_ROTL_LANE  1u
#define QDMSAN_OOB_COUNT_LANE 2u
#define QDMSAN_UAF_SUM_LANE   3u
#define QDMSAN_UAF_ROTL_LANE  4u
#define QDMSAN_UAF_COUNT_LANE 5u
#define QDMSAN_FLAGS_LANE     6u

#define QDMSAN_ACCESS_ABI_VERSION UINT64_C(1)
#define QDMSAN_ACCESS_FLAG_REGISTRY UINT64_C(0x0000000100000000)
#define QDMSAN_ACCESS_FLAG_PRESTORE UINT64_C(0x0000000200000000)

/* Aux feedback ABI: must match LLVM dmsan_feedback.h. */
#define QDMSAN_FEEDBACK_MAP_BITS 16
#define QDMSAN_FEEDBACK_MAP_SIZE (1u << QDMSAN_FEEDBACK_MAP_BITS)
#define QDMSAN_SITE_CLASS_BITS 16
#define QDMSAN_SITE_CLASS_ENTRIES (1u << QDMSAN_SITE_CLASS_BITS)
#define QDMSAN_SITE_CLASS_BUCKETS 16u
#define QDMSAN_FEEDBACK_MAGIC 0x4644424bU
#define QDMSAN_FEEDBACK_VERSION 2U
#define QDMSAN_FEEDBACK_RUNTIME_SITE_NS 0x80000000u

struct qdmsan_feedback_header {
  uint32_t magic;
  uint32_t version;
  uint32_t map_size;
  uint32_t site_map_entries;
} __attribute__((packed, aligned(16)));

struct qdmsan_feedback_shm {
  struct qdmsan_feedback_header header;
  uint8_t map[QDMSAN_FEEDBACK_MAP_SIZE];
  uint16_t site_map[QDMSAN_SITE_CLASS_ENTRIES];
} __attribute__((aligned(64)));

/* Full/hash ABI v2: must match LLVM dmsan_map_full.h. */
#define QDMSAN_FULL_MAGIC 0x46554c4cU
#define QDMSAN_FULL_ENTRY_FLAG_COLLISION 1u
#define QDMSAN_FULL_MODE_HASH 1u
#define QDMSAN_FULL_ABI_VERSION 2u

struct qdmsan_qemu_full_entry {
  uint64_t value;
  uint64_t pc;
  uint32_t site_id;
  uint32_t flags;
  uint64_t reserved;
} __attribute__((packed, aligned(16)));

struct qdmsan_qemu_full_meta {
  uint64_t magic;
  uint64_t array_size;
  uint64_t write_index;
  uint64_t total_count;
  uint64_t overflow_count;
  uint64_t module_base;
  uint64_t mode;
  uint64_t abi_version;
} __attribute__((aligned(64)));

struct qdmsan_qemu_full_shm {
  struct qdmsan_qemu_full_meta meta;
  struct qdmsan_qemu_full_entry entries[];
};

/* Fast digest lane salts. The names match the legacy DMSAN ABI spelling. */
#define QDMSAN_POLY_R1  UINT64_C(0x9e3779b97f4a7c15)
#define QDMSAN_POLY_R2  UINT64_C(0x517cc1b727220a95)

/* Shared memory environment variable names (same as AFL++/LLVM DMSAN). */
#define QDMSAN_FAST_SHM_ENV_VAR  "__DMSAN_FAST_SHM_ID"
#define QDMSAN_FEEDBACK_SHM_ENV_VAR "__DMSAN_FEEDBACK_SHM_ID"
#define QDMSAN_POISON_SHM_ENV_VAR "__DMSPVAL_SHM_ID"
#define QDMSAN_FULL_SHM_ENV_VAR  "__DMSAN_FULL_SHM_ID"

enum qdmsan_check_mode {
  QDMSAN_CHECK_RAW = 0,
  QDMSAN_CHECK_RESULT = 1,
};

enum qdmsan_record_mode {
  QDMSAN_MODE_FAST = 0,
  QDMSAN_MODE_FAST_AUX = 1,
  QDMSAN_MODE_FULL = 2,
};

enum qdmsan_event_kind {
  QDMSAN_EVENT_CMP = 1,
  QDMSAN_EVENT_AND = 2,
  QDMSAN_EVENT_OR = 3,
  QDMSAN_EVENT_FCMP = 4,
  QDMSAN_EVENT_BRANCH = 5,
  QDMSAN_EVENT_SETCC = 6,
  QDMSAN_EVENT_CMOV = 7,
  QDMSAN_EVENT_LOAD_PTR = 8,
  QDMSAN_EVENT_STORE_PTR = 9,
  QDMSAN_EVENT_DIV = 10,
  QDMSAN_EVENT_ATOMIC = 11,
  QDMSAN_EVENT_INDIRECT = 12,
  QDMSAN_EVENT_SYSCALL = 13,
  QDMSAN_EVENT_LIBC = 14,
  QDMSAN_EVENT_X86_SPECIAL = 15,
};

#define QDMSAN_FAKESYS_NR 0xa2a5

enum qdmsan_action {
  QDMSAN_ACTION_PREMAIN = 1,
  QDMSAN_ACTION_MAIN_STARTED = 2,
  QDMSAN_ACTION_POISON = 3,
  QDMSAN_ACTION_SUPPRESS_ENTER = 4,
  QDMSAN_ACTION_SUPPRESS_LEAVE = 5,
  QDMSAN_ACTION_RECORD = 6,
  QDMSAN_ACTION_FIXED_RAND_RAW = 7,
  QDMSAN_ACTION_FIXED_RAND_BYTES = 8,
  QDMSAN_ACTION_FIXED_TIME_SEC = 9,
  QDMSAN_ACTION_FIXED_TIME_USEC = 10,
  QDMSAN_ACTION_REGION_ADD = 11,
  QDMSAN_ACTION_REGION_REMOVE = 12,
};

enum qdmsan_region_type {
  QDMSAN_REGION_REDZONE = 1,
  QDMSAN_REGION_FREED = 2,
};

/* ------------------------------------------------------------------ */
/* BOGUS constant whitelist (from QMSan / Valgrind isBogusAtom)        */
/* Compiler-generated magic constants for inlined strlen/memchr etc.   */
/* AND-ing with these constants doesn't imply uninit-use of operand.   */
/* ------------------------------------------------------------------ */

static inline int qdmsan_is_bogus(uint64_t v) {
  return ((uint32_t)v) == UINT32_C(0xFEFEFEFF)
      || ((uint32_t)v) == UINT32_C(0x80808080)
      || ((uint32_t)v) == UINT32_C(0x7F7F7F7F)
      || ((uint32_t)v) == UINT32_C(0x7EFEFEFF)
      || ((uint32_t)v) == UINT32_C(0x81010100)
      || v == UINT64_C(0xFFFFFFFFFEFEFEFF)
      || v == UINT64_C(0xFEFEFEFEFEFEFEFF)
      || v == UINT64_C(0x0000000000008080)
      || v == UINT64_C(0x8080808080808080)
      || v == UINT64_C(0x0101010101010101);
}

#define QDMSAN_IS_BOGUS(v) qdmsan_is_bogus((uint64_t)(v))

/* ------------------------------------------------------------------ */
/* QEMU-side globals (defined in tcg-runtime.c)                        */
/* ------------------------------------------------------------------ */

extern struct qdmsan_qemu_fast_map *__qdmsan_qemu_map;
extern struct qdmsan_feedback_shm *__qdmsan_qemu_feedback_map;
extern struct qdmsan_qemu_full_shm *__qdmsan_qemu_full_map;
extern uint8_t *__qdmsan_qemu_poison;
extern __thread uint64_t __qdmsan_qemu_h1;
extern __thread uint64_t __qdmsan_qemu_h2;
extern __thread uint64_t __qdmsan_qemu_cnt;
extern int qdmsan_max_call_stack;
extern int qdmsan_check_mode;
extern int qdmsan_record_mode;
extern int qdmsan_stack_poison_enabled;
extern int qdmsan_pointer_checks_enabled;
extern int qdmsan_static_clean_pointer_prune_enabled;
extern int qdmsan_syscall_checks_enabled;
extern int qdmsan_branch_checks_enabled;
extern int qdmsan_cmp_branch_prune_enabled;
extern int qdmsan_main_started;
extern __thread int qdmsan_recording_suppressed;

struct qdmsan_shadow_stack_block {
  int index;
  target_ulong buf[QDMSAN_SHADOW_BK_SIZE];
  struct qdmsan_shadow_stack_block *next;
};

struct qdmsan_shadow_stack {
  int size;
  struct qdmsan_shadow_stack_block *first;
};

extern __thread struct qdmsan_shadow_stack qdmsan_shadow_stack;

/* App code segment range for NO_LIB-style filtering (0 = disabled).
 * Set from info->start_code / info->end_code in linux-user/main.c.   */
extern target_ulong qdmsan_app_start;
extern target_ulong qdmsan_app_end;
extern target_ulong qdmsan_app_base;

/* Called from linux-user/main.c at startup */
void qdmsan_qemu_init(void);

/* Thread exit commits the calling TLS; process exit quiesces all writers. */
void qdmsan_qemu_flush(void);
void qdmsan_qemu_flush_process(void);
/* Called within the guest fork exclusive section. */
void qdmsan_qemu_fork_start(void);
void qdmsan_qemu_fork_end(int child);

/* Translation-time gate for TCG-generated QDMSAN checkpoints. */
int qdmsan_should_emit_tcg_event(target_ulong pc);

void qdmsan_record_syscall(int num, target_ulong arg1, target_ulong arg2,
                           target_ulong arg3, target_ulong arg4,
                           target_ulong arg5, target_ulong arg6);
target_ulong qdmsan_actions_dispatcher(target_ulong action, target_ulong arg1,
                                        target_ulong arg2, target_ulong arg3);
uint64_t qdmsan_fixed_time_sec_next(void);
uint64_t qdmsan_fixed_tsc_next(void);
uint64_t qdmsan_fixed_rdrand_next(void);
void qdmsan_fill_fixed_rand_bytes(void *buf, size_t len);

#endif /* QDMSAN_QEMU_H */
