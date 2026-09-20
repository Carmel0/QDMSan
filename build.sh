#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
JOBS="${JOBS:-2}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo 'JOBS must be a positive integer' >&2; exit 2; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  echo 'This release supports Linux x86-64 hosts and targets.' >&2; exit 2;
}
for command in cc c++ make meson ninja python3 pkg-config; do
  command -v "$command" >/dev/null || { echo "Missing build tool: $command" >&2; exit 2; }
done
pkg-config --exists glib-2.0 || { echo 'Missing glib-2.0 development files' >&2; exit 2; }
QEMU="$ROOT/qemu_mode/qemuafl"
for source in qemuafl/qdmsan-qemu.h capstone/Makefile slirp/meson.build ui/keycodemapdb/README; do
  [[ -f "$QEMU/$source" ]] || { echo "Missing vendored source: $source" >&2; exit 2; }
done
mkdir -p "$ROOT/build/bin" "$ROOT/build-logs"
make -C "$ROOT" -j"$JOBS" NO_PYTHON=1 afl-fuzz afl-showmap 2>&1 | tee "$ROOT/build-logs/afl.log"
make -C "$ROOT/utils/qdmsan-diff" -j"$JOBS" 2>&1 | tee "$ROOT/build-logs/replay.log"
make -C "$ROOT/qemu_mode/libqdmsan" -j"$JOBS" 2>&1 | tee "$ROOT/build-logs/runtime.log"
for header in config.h cmplog.h snapshot-inl.h types.h; do
  cp "$ROOT/include/$header" "$QEMU/qemuafl/imported/$header"
done
mkdir -p "$QEMU/build-release"
python3 - "$ROOT" <<'PY' 2>&1 | tee "$ROOT/build-logs/qemu-configure.log"
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
qemu = root / 'qemu_mode/qemuafl'
args = json.loads((root / 'build-support/qemu-configure.json').read_text())
subprocess.run([str(qemu / 'configure'), *args], cwd=qemu / 'build-release', check=True)
PY
ninja -C "$QEMU/build-release" -j"$JOBS" qemu-x86_64 2>&1 | tee "$ROOT/build-logs/qemu-build.log"

# Stage a matched set only after every component built successfully.
install -m 755 "$ROOT/afl-fuzz" "$ROOT/afl-showmap" "$ROOT/utils/qdmsan-diff/qdmsan-diff" "$ROOT/libqdmsan.so" "$ROOT/build/bin/"
install -m 755 "$QEMU/build-release/qemu-x86_64" "$ROOT/build/bin/afl-qemu-trace"
python3 - "$ROOT" <<'PY'
import hashlib, json, pathlib, platform, subprocess, sys
root = pathlib.Path(sys.argv[1])
out = root / 'build/bin'
names = ['afl-fuzz', 'afl-showmap', 'qdmsan-diff', 'libqdmsan.so', 'afl-qemu-trace']
(out / 'SHA256SUMS').write_text(''.join(hashlib.sha256((out / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in names))
try:
    commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True, stderr=subprocess.DEVNULL).strip()
    dirty = bool(subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=no'], text=True))
except (OSError, subprocess.CalledProcessError):
    commit, dirty = None, None
(out / 'BUILD.json').write_text(json.dumps({'source_commit': commit, 'tracked_changes': dirty,
    'host': platform.platform(), 'note': 'Release build; not the frozen paper measurement binaries.'}, indent=2) + '\n')
PY
echo "Build complete: $ROOT/build/bin"
echo 'Run ./test.sh to check the matched components.'
