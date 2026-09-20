/*
   american fuzzy lop++ - high-performance binary-only instrumentation
   -------------------------------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
   counters by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 3.1.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include "common.h"
#include "qdmsan-qemu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"

uint32_t afl_hash_ip(uint64_t);

#if TARGET_LONG_BITS == 64
  #define _DEFAULT_MO MO_64
#else
  #define _DEFAULT_MO MO_32
#endif

static inline int qdmsan_gen_should_emit(target_ulong cur_loc) {
  return __qdmsan_qemu_map && qdmsan_should_emit_tcg_event(cur_loc);
}

/*
 * qdmsan_gen_checkpoint — TCG-level icmp checkpoint for CMP/SUB.
 * Records both operands via QDMSAN fast/full event helpers.
 * Emitted only with a fast map and a permitted main-program instruction.
 */
static void qdmsan_gen_checkpoint(target_ulong cur_loc, TCGv arg1, TCGv arg2,
                                   MemOp ot) {
  if (!qdmsan_gen_should_emit(cur_loc)) return;
  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  switch (ot & MO_SIZE) {
    case MO_64: gen_helper_qdmsan_checkpoint_64(cur_loc_v, arg1, arg2); break;
    case MO_32: gen_helper_qdmsan_checkpoint_32(cur_loc_v, arg1, arg2); break;
    case MO_16: gen_helper_qdmsan_checkpoint_16(cur_loc_v, arg1, arg2); break;
    default:    gen_helper_qdmsan_checkpoint_8(cur_loc_v, arg1, arg2);  break;
  }
  tcg_temp_free(cur_loc_v);
}

static void qdmsan_gen_checkpoint_imm(target_ulong cur_loc, TCGv arg,
                                       TCGv imm, MemOp ot) {
  if (!qdmsan_gen_should_emit(cur_loc)) return;
  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  switch (ot & MO_SIZE) {
    case MO_64: gen_helper_qdmsan_checkpoint_imm_64(cur_loc_v, arg, imm); break;
    case MO_32: gen_helper_qdmsan_checkpoint_imm_32(cur_loc_v, arg, imm); break;
    case MO_16: gen_helper_qdmsan_checkpoint_imm_16(cur_loc_v, arg, imm); break;
    default:    gen_helper_qdmsan_checkpoint_imm_8(cur_loc_v, arg, imm);  break;
  }
  tcg_temp_free(cur_loc_v);
}

/*
 * qdmsan_gen_and_checkpoint — AND/TEST: skip if either operand is 0
 * (absorbing element: 0 AND x == 0 regardless of x).
 */
static void qdmsan_gen_and_checkpoint(target_ulong cur_loc, TCGv arg1,
                                       TCGv arg2, MemOp ot) {
  if (!qdmsan_gen_should_emit(cur_loc)) return;
  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  switch (ot & MO_SIZE) {
    case MO_64: gen_helper_qdmsan_and_checkpoint_64(cur_loc_v, arg1, arg2); break;
    case MO_32: gen_helper_qdmsan_and_checkpoint_32(cur_loc_v, arg1, arg2); break;
    case MO_16: gen_helper_qdmsan_and_checkpoint_16(cur_loc_v, arg1, arg2); break;
    default:    gen_helper_qdmsan_and_checkpoint_8(cur_loc_v, arg1, arg2);  break;
  }
  tcg_temp_free(cur_loc_v);
}

static void qdmsan_gen_and_checkpoint_imm(target_ulong cur_loc, TCGv arg,
                                           TCGv imm, MemOp ot) {
  if (!qdmsan_gen_should_emit(cur_loc)) return;
  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  switch (ot & MO_SIZE) {
    case MO_64: gen_helper_qdmsan_and_checkpoint_imm_64(cur_loc_v, arg, imm); break;
    case MO_32: gen_helper_qdmsan_and_checkpoint_imm_32(cur_loc_v, arg, imm); break;
    case MO_16: gen_helper_qdmsan_and_checkpoint_imm_16(cur_loc_v, arg, imm); break;
    default:    gen_helper_qdmsan_and_checkpoint_imm_8(cur_loc_v, arg, imm);  break;
  }
  tcg_temp_free(cur_loc_v);
}

/*
 * qdmsan_gen_ucomis_checkpoint — emit TCG call after ucomiss/ucomisd/comiss/comisd.
 * The helper reads env->cc_src (set by the SSE compare helper to one of four
 * EFLAGS values) and records it as the checkpoint value.
 */
static void qdmsan_gen_ucomis_checkpoint(target_ulong cur_loc) {
  if (!qdmsan_gen_should_emit(cur_loc)) return;
  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  gen_helper_qdmsan_ucomis_checkpoint(cur_loc_v, cpu_env);
  tcg_temp_free(cur_loc_v);
}

static void qdmsan_gen_value_checkpoint(target_ulong cur_loc, TCGv value,
                                         target_ulong kind) {
  if (!qdmsan_gen_should_emit(cur_loc)) return;
  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  TCGv kind_v = tcg_const_tl(kind);
  gen_helper_qdmsan_value_checkpoint(cur_loc_v, value, kind_v);
  tcg_temp_free(kind_v);
  tcg_temp_free(cur_loc_v);
}

static void qdmsan_gen_ptr_checkpoint(target_ulong cur_loc, TCGv value,
                                       target_ulong kind) {
  if (!qdmsan_pointer_checks_enabled || !qdmsan_gen_should_emit(cur_loc)) return;
  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  TCGv kind_v = tcg_const_tl(kind);
  gen_helper_qdmsan_ptr_checkpoint(cur_loc_v, value, kind_v);
  tcg_temp_free(kind_v);
  tcg_temp_free(cur_loc_v);
}

/*
 * qdmsan_gen_stack_alloc — emit TCG call to fill [new_sp, old_sp) with magic.
 * Called after SUB RSP, N when destination is R_ESP.
 * new_sp = cpu_regs[R_ESP] (already updated), old_sp = s->cc_srcT (saved before SUB).
 */
static void qdmsan_gen_stack_alloc(TCGv new_sp, TCGv old_sp) {
  if (!use_qdmsan) return;
  gen_helper_qdmsan_stack_alloc(new_sp, old_sp);
}

/*
 * qdmsan_gen_call_fill — emit TCG call to fill the x86-64 red zone.
 * Called at CALL instruction, before gen_push_v (return address push).
 * caller_rsp is cpu_regs[R_ESP] at that point (before the push).
 */
static void qdmsan_gen_call_fill(TCGv caller_rsp) {
  if (!use_qdmsan) return;
  gen_helper_qdmsan_call_fill(caller_rsp);
}

static void afl_gen_compcov(target_ulong cur_loc, TCGv arg1, TCGv arg2,
                            MemOp ot, int is_imm) {

  if (!afl_must_instrument(cur_loc)) return;

  if (__afl_cmp_map) {

    cur_loc = (uintptr_t)(afl_hash_ip((uint64_t)cur_loc));
    cur_loc &= (CMP_MAP_W - 1);

    TCGv cur_loc_v = tcg_const_tl(cur_loc);

    switch (ot & MO_SIZE) {

      case MO_64:
        gen_helper_afl_cmplog_64(cur_loc_v, arg1, arg2);
        break;
      case MO_32:
        gen_helper_afl_cmplog_32(cur_loc_v, arg1, arg2);
        break;
      case MO_16:
        gen_helper_afl_cmplog_16(cur_loc_v, arg1, arg2);
        break;
      case MO_8:
        gen_helper_afl_cmplog_8(cur_loc_v, arg1, arg2);
        break;
      default:
        break;

    }

    tcg_temp_free(cur_loc_v);

  } else if (afl_compcov_level) {

    if (!is_imm && afl_compcov_level < 2) return;

    cur_loc = (uintptr_t)(afl_hash_ip((uint64_t)cur_loc));
    cur_loc &= (MAP_SIZE - 1);

    TCGv cur_loc_v = tcg_const_tl(cur_loc);

    if (cur_loc >= afl_inst_rms) return;

    switch (ot & MO_SIZE) {

      case MO_64:
        gen_helper_afl_compcov_64(cur_loc_v, arg1, arg2);
        break;
      case MO_32:
        gen_helper_afl_compcov_32(cur_loc_v, arg1, arg2);
        break;
      case MO_16:
        gen_helper_afl_compcov_16(cur_loc_v, arg1, arg2);
        break;
      default:
        break;

    }

    tcg_temp_free(cur_loc_v);

  }

}

/* Routines for debug */
/*
static void log_x86_saved_gpr(void) {

  static const char reg_names[CPU_NB_REGS][4] = {

#ifdef TARGET_X86_64
        [R_EAX] = "rax",
        [R_EBX] = "rbx",
        [R_ECX] = "rcx",
        [R_EDX] = "rdx",
        [R_ESI] = "rsi",
        [R_EDI] = "rdi",
        [R_EBP] = "rbp",
        [R_ESP] = "rsp",
        [8]  = "r8",
        [9]  = "r9",
        [10] = "r10",
        [11] = "r11",
        [12] = "r12",
        [13] = "r13",
        [14] = "r14",
        [15] = "r15",
#else
        [R_EAX] = "eax",
        [R_EBX] = "ebx",
        [R_ECX] = "ecx",
        [R_EDX] = "edx",
        [R_ESI] = "esi",
        [R_EDI] = "edi",
        [R_EBP] = "ebp",
        [R_ESP] = "esp",
#endif

    };

  int i;
  for (i = 0; i < CPU_NB_REGS; ++i) {

    fprintf(stderr, "%s = %lx\n", reg_names[i], persistent_saved_gpr[i]);

  }

}

static void log_x86_sp_content(void) {

  fprintf(stderr, ">> SP = %lx -> %lx\n", persistent_saved_gpr[R_ESP],
*(unsigned long*)persistent_saved_gpr[R_ESP]);

}*/

static void restore_sp_for_persistent(TCGv sp) {

  if (!persistent_save_gpr && afl_persistent_ret_addr == 0) {

    TCGv_ptr stack_off_ptr = tcg_const_ptr(&persistent_stack_offset);
    TCGv     stack_off = tcg_temp_new();
    tcg_gen_ld_tl(stack_off, stack_off_ptr, 0);
    tcg_gen_sub_tl(sp, sp, stack_off);
    tcg_temp_free(stack_off);

  }

}

