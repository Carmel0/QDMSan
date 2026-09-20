#!/usr/bin/env python3
"""Compile production calibration and execution hooks with a synthetic child.

The selected functions are copied verbatim into the build directory. The driver
simulates child coverage/signatures, while production bitmap and hash code run.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
out = args.output or Path(tempfile.mkdtemp(prefix='qdmsan-calibration-test-'))
out.mkdir(parents=True, exist_ok=True)
out = out.resolve()
source = (root / 'src/afl-fuzz-run.c').read_text()
# Boundaries use complete neighboring top-level declarations, not rewritten
# statements, so tests execute the exact production function bodies.
execute = source[source.index('fsrv_run_result_t __attribute__((hot)) fuzz_run_target('):
                 source.index('/* Write modified data to file for testing.')]
calibrate = source[source.index('u8 calibrate_case('):source.index('/* Do not sync items')]
fixture = (root / 'test_qdmsan/host_calibration_fixture.c').read_text()
generated = out / 'calibration.c'
generated.write_text('#include "afl-fuzz.h"\n#include "afl-ijon-min.h"\n'
                     '#include "cmplog.h"\n#include "dmsanfuzz.h"\n'
                     + execute + '\n' + calibrate + '\n' + fixture)
binary = out / 'host-calibration'
command = [os.environ.get('CC', 'cc'), '-O2', '-g', '-ffunction-sections',
           '-fdata-sections', '-Wl,--gc-sections', '-Wno-pointer-sign',
           '-I', str(root / 'include'), '-DAFL_PATH="/usr/local/lib/afl"',
           '-DBIN_PATH="/usr/local/bin"', '-DDOC_PATH="/usr/local/share/doc/afl"',
           str(generated), str(root / 'src/afl-fuzz-bitmap.c'),
           str(root / 'src/afl-performance.c'), str(root / 'src/afl-common.c'),
           '-ldl', '-o', str(binary)]
build = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(out / 'build.log').write_bytes(build.stdout)
if build.returncode:
    raise SystemExit(build.stdout.decode())
result = subprocess.run([binary], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(out / 'results.log').write_bytes(result.stdout)
print(result.stdout.decode(), end='')
raise SystemExit(result.returncode)
