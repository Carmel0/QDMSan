#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-cc}"
TMP_BIN="$(mktemp "${TMPDIR:-/tmp}/qdmsan-plane-unit.XXXXXX")"
trap 'rm -f "$TMP_BIN"' EXIT

"$CC" -std=c11 -Wall -Wextra -Werror -I"$ROOT_DIR/include" \
  "$ROOT_DIR/test_qdmsan/unit_three_plane_verdict.c" -o "$TMP_BIN"
"$TMP_BIN"
echo "three_plane_verdict_unit: PASS"
