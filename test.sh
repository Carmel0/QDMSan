#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for binary in afl-fuzz afl-showmap qdmsan-diff afl-qemu-trace libqdmsan.so; do
  [[ -f "$ROOT/build/bin/$binary" ]] || { echo "Run ./build.sh first (missing $binary)" >&2; exit 2; }
done
# Clear inherited detector settings, then bind the freshly built components.
exec python3 - "$ROOT" <<'PY'
import os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
env = {k: v for k, v in os.environ.items() if not k.startswith(('AFL_', 'QDMSAN_', 'DMSAN_', '__DMS', '__AFL_', 'QEMU_')) and k not in ('LD_PRELOAD', 'LD_LIBRARY_PATH')}
binary = root / 'build/bin'
env.update(QDMSAN_DIFF=str(binary / 'qdmsan-diff'), AFL_QDMSAN_QEMU=str(binary / 'afl-qemu-trace'),
           AFL_QDMSAN_LIB=str(binary / 'libqdmsan.so'), QDMSAN_AFL_FUZZ=str(binary / 'afl-fuzz'), AFL_PATH=str(binary), AFL_PRELOAD=str(binary / 'libqdmsan.so'))
for name in ('run_three_plane_unit.sh', 'run_three_plane_smoke.sh', 'run_inline_full_smoke.sh'):
    subprocess.run(['bash', str(root / 'test_qdmsan' / name)], cwd=root, env=env, stdin=subprocess.DEVNULL, check=True)
tests = root / 'build/tests'
tests.mkdir(parents=True, exist_ok=True)
commands = [
    ['python3', 'test_qdmsan/run_host_reliability.py', '--qemu', str(binary / 'afl-qemu-trace'),
     '--runtime', str(binary / 'libqdmsan.so'), '--diff', str(binary / 'qdmsan-diff'), '--output', str(tests / 'host')],
    ['python3', 'test_qdmsan/run_host_calibration.py', '--output', str(tests / 'calibration')],
    ['python3', 'test_qdmsan/runtime_release_test.py', '--qdmsan-diff', str(binary / 'qdmsan-diff'),
     '--qemu', str(binary / 'afl-qemu-trace'), '--preload', str(binary / 'libqdmsan.so'), '--out-dir', str(tests / 'runtime')],
]
for command in commands:
    subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL, check=True)
print('QDMSan component and release regression checks passed.')
PY
