#!/usr/bin/env bash
# QDMSan uses the vendored QEMU-AFL tree; do not replace it from upstream.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/build.sh" "$@"
