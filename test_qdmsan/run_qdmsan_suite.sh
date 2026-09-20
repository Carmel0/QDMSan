#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${QDMSAN_TEST_BUILD_DIR:-$ROOT_DIR/test_qdmsan/build}"
OUT_DIR="${QDMSAN_TEST_OUT_DIR:-$ROOT_DIR/test_qdmsan/results}"
QDMSAN_DIFF="${QDMSAN_DIFF:-$ROOT_DIR/utils/qdmsan-diff/qdmsan-diff}"
CLANG="${CLANG:-clang}"
CXX="${CXX:-clang++}"
QDMSAN_DIFF_TIMEOUT_MS="${QDMSAN_DIFF_TIMEOUT_MS:-5000}"
QDMSAN_CASE_TIMEOUT="${QDMSAN_CASE_TIMEOUT:-20s}"
SELECTOR="${1:-local}"

usage() {
  cat >&2 <<EOF
usage: $0 [local|nondet|raw|result|all]
EOF
  exit 2
}

case "$SELECTOR" in
  local|nondet|raw|result|all) ;;
  *) usage ;;
esac

if [[ ! -x "$QDMSAN_DIFF" ]]; then
  echo "missing qdmsan-diff: $QDMSAN_DIFF" >&2
  exit 2
fi

mkdir -p "$BUILD_DIR" "$OUT_DIR"

RESULTS="$OUT_DIR/${SELECTOR}_results.tsv"
SUMMARY="$OUT_DIR/${SELECTOR}_summary.md"

compile_case() {
  local origin="$1"
  local src="$2"
  local bin="$3"
  local flags="$4"
  local link_flags="$5"
  local compiler="$CLANG"
  local -a extra=()
  local -a case_flags=()
  local -a links=()

  if [[ "$flags" != "-" && -n "$flags" ]]; then
    read -r -a case_flags <<< "$flags"
  fi
  if [[ "$link_flags" != "-" && -n "$link_flags" ]]; then
    read -r -a links <<< "$link_flags"
  fi

  case "$src" in
    *.cc|*.cpp|*.cxx)
      compiler="$CXX"
      extra=(-std=c++17)
      ;;
  esac

  "$compiler" -D_GNU_SOURCE -O1 -g -fno-omit-frame-pointer -fno-builtin \
    -Wno-uninitialized -Wno-unused-command-line-argument -Wno-strncat-size \
    "${extra[@]}" "$src" "${case_flags[@]}" "${links[@]}" -o "$bin" \
    < /dev/null
}

run_case() {
  local origin="$1"
  local bin="$2"
  local log="$3"
  local mode="$4"
  local check_mode="$5"
  local kind="${6:-}"
  local -a env_prefix=(env)
  local -a env_assignments=()

  # The OOB/UAF heap planes are opt-in; the heap witnesses and the allocator
  # controls enable them, and every other row runs with them forced off.
  case "$kind" in
    heap-*|three-planes|allocator-api|libc-nested-free)
      env_assignments+=(AFL_QDMSAN_HEAP_PLANES=1)
      ;;
    *)
      env_prefix+=(-u AFL_QDMSAN_HEAP_PLANES)
      ;;
  esac

  set +e
  "${env_prefix[@]}" "${env_assignments[@]}" timeout "$QDMSAN_CASE_TIMEOUT" "$QDMSAN_DIFF" -Q \
    -m "$mode" -c "$check_mode" -t "$QDMSAN_DIFF_TIMEOUT_MS" -- "$bin" \
    >"$log.out" 2>"$log.err" < /dev/null
  local rc=$?
  set -e

  case "$rc" in
    0) echo clean ;;
    1) echo report ;;
    2) echo nondet ;;
    3) echo crash ;;
    4|124) echo timeout ;;
    *) echo "runtime_error:$rc" ;;
  esac
}

should_run_row() {
  local origin="$1"
  local kind="$2"
  local check_mode="$3"

  case "$SELECTOR" in
    local|all) return 0 ;;
    nondet) [[ "$kind" == nondet-* ]] ;;
    raw) [[ "$check_mode" == "raw" ]] ;;
    result) [[ "$check_mode" == "result" ]] ;;
  esac
}

printf 'origin\tset\tkind\tpath\tsource_ref\texpected\tactual\tstatus\tcheck_mode\tmode\tcompile_flags\tlink_flags\ttitle\n' > "$RESULTS"

total=0
pass=0
fail=0
compile_fail=0
runtime_error=0

manifest="$ROOT_DIR/test_qdmsan/manifests/qdmsan_local.tsv"
if [[ ! -f "$manifest" ]]; then
  echo "missing manifest: $manifest" >&2
  exit 2
fi

while IFS=$'\t' read -r origin set_name kind rel source_ref expected check_mode mode compile_flags link_flags title; do
  [[ "$origin" == "origin" || -z "$origin" || "$origin" == \#* ]] && continue
  should_run_row "$origin" "$kind" "$check_mode" || continue

  case "$origin" in
    local) src="$ROOT_DIR/test_qdmsan/$rel" ;;
    *) echo "unknown origin '$origin' in $manifest" >&2; exit 2 ;;
  esac

  total=$((total + 1))
  safe_name="${origin}__${check_mode}__${mode}__${rel//\//__}"
  safe_name="${safe_name//[^A-Za-z0-9_.-]/_}"
  bin="$BUILD_DIR/$safe_name"
  log="$OUT_DIR/$safe_name"

  if [[ ! -f "$src" ]]; then
    actual="missing_source"
    status="FAIL"
    compile_fail=$((compile_fail + 1))
  elif ! compile_case "$origin" "$src" "$bin" "$compile_flags" "$link_flags" \
      >"$log.compile.out" 2>"$log.compile.err"; then
    actual="compile_error"
    status="FAIL"
    compile_fail=$((compile_fail + 1))
  else
    actual="$(run_case "$origin" "$bin" "$log" "$mode" "$check_mode" "$kind")"
    [[ "$actual" == runtime_error:* ]] && runtime_error=$((runtime_error + 1))
    if [[ "$actual" == "$expected" ]]; then
      status="PASS"
    else
      status="FAIL"
    fi
  fi

  [[ "$status" == "PASS" ]] && pass=$((pass + 1)) || fail=$((fail + 1))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$origin" "$set_name" "$kind" "$rel" "$source_ref" "$expected" \
    "$actual" "$status" "$check_mode" "$mode" "${compile_flags:-"-"}" \
    "${link_flags:-"-"}" "${title:-"-"}" >> "$RESULTS"
done < "$manifest"

cat > "$SUMMARY" <<EOF
# QDMSan test results

Date: $(date +%F)

Selector: $SELECTOR

\`\`\`text
total=$total pass=$pass fail=$fail
compile_fail=$compile_fail runtime_error=$runtime_error
\`\`\`

Artifacts:

- Results: $RESULTS
- Build dir: $BUILD_DIR
EOF

printf 'summary\tselector=%s total=%d pass=%d fail=%d compile_fail=%d runtime_error=%d results=%s\n' \
  "$SELECTOR" "$total" "$pass" "$fail" "$compile_fail" "$runtime_error" \
  "$RESULTS"

[[ "$fail" == 0 && "$compile_fail" == 0 && "$runtime_error" == 0 ]]
