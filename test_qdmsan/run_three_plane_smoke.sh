#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-clang}"
QDMSAN_DIFF="${QDMSAN_DIFF:-$ROOT_DIR/utils/qdmsan-diff/qdmsan-diff}"
QEMU="${AFL_QDMSAN_QEMU:-$ROOT_DIR/afl-qemu-trace}"
RUNTIME="${AFL_QDMSAN_LIB:-$ROOT_DIR/libqdmsan.so}"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/qdmsan-three-plane.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

for artifact in "$QDMSAN_DIFF" "$QEMU"; do
  if [[ ! -x "$artifact" ]]; then
    echo "missing executable: $artifact" >&2
    exit 2
  fi
done
if [[ ! -r "$RUNTIME" ]]; then
  echo "missing runtime: $RUNTIME" >&2
  exit 2
fi

compile_case() {
  local src="$1"
  local bin="$2"
  "$CC" -D_GNU_SOURCE -O1 -g -fno-omit-frame-pointer -fno-builtin \
    -Wno-uninitialized -Wno-tautological-compare \
    "$ROOT_DIR/test_qdmsan/$src" -o "$bin"
}

run_bug_case() {
  local name="$1"
  local src="$2"
  local planes="$3"
  local mask="$4"
  local bin="$TMP_ROOT/$name"
  local log="$TMP_ROOT/$name.log"
  compile_case "$src" "$bin"

  set +e
  "$QDMSAN_DIFF" -q "$QEMU" -l "$RUNTIME" -m fast -c raw -- "$bin" \
    >"$log" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    cat "$log" >&2
    echo "$name: expected bug exit 1, got $rc" >&2
    exit 1
  fi
  local expected="runs=3 candidate=$planes($mask) confirmed=$planes($mask) nondet=none(0x00)"
  if ! grep -Fq "$expected" "$log"; then
    cat "$log" >&2
    echo "$name: missing exact 2+1 plane verdict: $expected" >&2
    exit 1
  fi
  echo "$name: PASS ($planes)"
}

run_clean_case() {
  local name="$1"
  local src="$2"
  local bin="$TMP_ROOT/$name"
  local log="$TMP_ROOT/$name.log"
  compile_case "$src" "$bin"

  set +e
  "$QDMSAN_DIFF" -q "$QEMU" -l "$RUNTIME" -m fast -c raw -- "$bin" \
    >"$log" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -ne 0 ]] ||
     ! grep -Fq "runs=2 candidate=none(0x00) confirmed=none(0x00) nondet=none(0x00)" "$log"; then
    cat "$log" >&2
    echo "$name: expected clean two-run fast path, got exit $rc" >&2
    exit 1
  fi
  echo "$name: PASS (clean in 2 runs)"
}

# The OOB/UAF heap planes are opt-in, so the three-plane cases enable them.
export AFL_QDMSAN_HEAP_PLANES=1
run_bug_case uum cases/tp/raw_cmp_operand_reports.c UUM 0x01
run_bug_case oob_read cases/tp/heap_oob_read_reports.c OOB 0x02
run_bug_case oob_write cases/tp/heap_oob_write_reports.c OOB 0x02
run_bug_case oob_partial_write cases/tp/heap_oob_partial_write_reports.c OOB 0x02
run_bug_case uaf_read cases/tp/heap_uaf_read_reports.c UAF 0x04
run_bug_case uaf_write cases/tp/heap_uaf_write_reports.c UAF 0x04
run_bug_case all_three cases/tp/three_memory_planes_report.c 'UUM|OOB|UAF' 0x07
run_clean_case in_bounds cases/tn/heap_in_bounds_clean.c

# Default configuration: no access helper and no region registry, so the heap
# witnesses stay clean after two runs and the three-plane witness keeps only
# its UUM report.  The two gates are then asserted separately below.
unset AFL_QDMSAN_HEAP_PLANES
run_clean_case default_off_oob_read cases/tp/heap_oob_read_reports.c
run_clean_case default_off_oob_write cases/tp/heap_oob_write_reports.c
run_clean_case default_off_uaf_read cases/tp/heap_uaf_read_reports.c
run_clean_case default_off_uaf_write cases/tp/heap_uaf_write_reports.c
run_bug_case default_off_all_three cases/tp/three_memory_planes_report.c UUM 0x01
run_bug_case default_off_uum cases/tp/raw_cmp_operand_reports.c UUM 0x01

# Translation gate (tcg-op.c): with the heap planes off, the op stream holds
# no access helper call; with them on it holds some (positive control).
count_access_helpers() {
  local ops="$TMP_ROOT/ops.log"
  rm -f "$ops"
  AFL_USE_QDMSAN=1 "$QEMU" -d op -D "$ops" "$TMP_ROOT/default_off_all_three" \
    >/dev/null 2>&1 || true
  grep -c 'call qdmsan_access' "$ops" || true
}
off_calls="$(count_access_helpers)"
on_calls="$(export AFL_QDMSAN_HEAP_PLANES=1; count_access_helpers)"
if [[ "$off_calls" -ne 0 || "$on_calls" -le 0 ]]; then
  echo "translation gate: expected 0 qdmsan_access calls off and >0 on, got $off_calls and $on_calls" >&2
  exit 1
fi
echo "default_off_translation_gate: PASS (0 off, $on_calls on)"

# Dispatcher gate (tcg-runtime.c): REGION_ADD is accepted but ignored, so the
# access ABI lane (padding[6]) stays zero off and is set on.
if ! grep -q 'abi=' "$TMP_ROOT/default_off_all_three.log" ||
   grep -Eq 'abi=0x0*[1-9a-f]' "$TMP_ROOT/default_off_all_three.log" ||
   ! grep -Fq 'abi=0x0000000300000001' "$TMP_ROOT/all_three.log"; then
  cat "$TMP_ROOT/default_off_all_three.log" "$TMP_ROOT/all_three.log" >&2
  echo "dispatcher gate: expected abi=0 with heap planes off and abi=0x0000000300000001 on" >&2
  exit 1
fi
echo "default_off_dispatcher_gate: PASS"

echo "three_plane_2plus1_smoke: PASS"
