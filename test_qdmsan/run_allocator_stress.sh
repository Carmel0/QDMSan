#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-cc}"
RUNTIME="${AFL_QDMSAN_LIB:-$ROOT_DIR/libqdmsan.so}"
TMP_BIN="$(mktemp "${TMPDIR:-/tmp}/qdmsan-allocator-stress.XXXXXX")"
trap 'rm -f "$TMP_BIN"' EXIT

if [[ ! -r "$RUNTIME" ]]; then
  echo "missing libqdmsan runtime: $RUNTIME" >&2
  exit 2
fi

"$CC" -O2 -Wall -Wextra -Werror -pthread \
  "$ROOT_DIR/test_qdmsan/allocator_thread_stress.c" -o "$TMP_BIN"

env LD_PRELOAD="$RUNTIME" AFL_QDMSAN_QUARANTINE_MB=1 "$TMP_BIN"
echo "allocator_thread_stress: PASS"
