#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLANG="${CLANG:-clang}"
FUZZ="${QDMSAN_AFL_FUZZ:-$ROOT_DIR/build/bin/afl-fuzz}"
SRC="$ROOT_DIR/test_qdmsan/cases/tp/three_memory_planes_report.c"

if [[ ! -x "$FUZZ" || ! -x "$ROOT_DIR/afl-qemu-trace" ||
      ! -r "$ROOT_DIR/libqdmsan.so" ]]; then
  echo "missing rebuilt afl-fuzz, afl-qemu-trace, or libqdmsan.so" >&2
  exit 2
fi

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/qdmsan-inline-three.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT
IN_DIR="$TMP_ROOT/in"
OUT_DIR="$TMP_ROOT/out"
BIN="$TMP_ROOT/target"
LOG="$TMP_ROOT/fuzz.log"
mkdir -p "$IN_DIR"
printf 'x' > "$IN_DIR/seed"

"$CLANG" -D_GNU_SOURCE -O1 -g -fno-omit-frame-pointer -fno-builtin \
  -Wno-uninitialized "$SRC" -o "$BIN"

set +e
env AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 \
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_BENCH_JUST_ONE=1 \
  AFL_QDMSAN_MODE=fast AFL_QDMSAN_HEAP_PLANES=1 \
  timeout 20s "$FUZZ" -Q -i "$IN_DIR" -o "$OUT_DIR" -m none -- "$BIN" \
  >"$LOG" 2>&1
FUZZ_STATUS=$?
set -e
if [[ "$FUZZ_STATUS" -ne 0 && "$FUZZ_STATUS" -ne 124 ]]; then
  tail -n 120 "$LOG" >&2 || true
  echo "afl-fuzz exited with unexpected status $FUZZ_STATUS" >&2
  exit "$FUZZ_STATUS"
fi

STATS="$OUT_DIR/default/fuzzer_stats"
FIND_DIR="$OUT_DIR/default/dmsan_findings"
if [[ ! -f "$STATS" ]]; then
  tail -n 120 "$LOG" >&2 || true
  echo "missing fuzzer_stats" >&2
  exit 1
fi

get_stat() {
  awk -F: -v key="$1" '
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2);
      print $2;
      exit;
    }' "$STATS"
}

CHECKS="$(get_stat dmsan_checks)"
BUGS="$(get_stat dmsan_bugs)"
SAVED="$(get_stat saved_dmsan_findings)"
if [[ -z "$CHECKS" || -z "$BUGS" || -z "$SAVED" ]] ||
   (( CHECKS <= 0 || BUGS <= 0 || SAVED <= 0 )); then
  cat "$STATS" >&2
  echo "expected an inline QDMSAN finding" >&2
  exit 1
fi

FINDINGS=0
if [[ -d "$FIND_DIR" ]]; then
  FINDINGS="$(find "$FIND_DIR" -maxdepth 1 -type f \
    -name 'id:*,result:bug,planes:UUM|OOB|UAF,*' | wc -l | tr -d ' ')"
fi
if (( FINDINGS <= 0 )); then
  find "$FIND_DIR" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort >&2 || true
  echo "missing finding classified as UUM|OOB|UAF" >&2
  exit 1
fi

echo "inline_three_plane: checks=$CHECKS bugs=$BUGS saved=$SAVED findings=$FINDINGS"
