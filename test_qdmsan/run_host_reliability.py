#!/usr/bin/env python3
"""Synthetic host regression tests; requires built QDMSan components.

Usage: run_host_reliability.py --qemu PATH --runtime PATH [--diff PATH]
All generated files live in --output or a temporary directory, never the source.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--qemu', type=Path, required=True)
parser.add_argument('--runtime', type=Path, required=True)
parser.add_argument('--diff', type=Path, default=ROOT / 'utils/qdmsan-diff/qdmsan-diff')
parser.add_argument('--output', type=Path)
args = parser.parse_args()
work = args.output or Path(tempfile.mkdtemp(prefix='qdmsan-host-tests-'))
work.mkdir(parents=True, exist_ok=True)
work = work.resolve()
env = {k: v for k, v in os.environ.items()
       if not k.startswith(('AFL_', 'QEMU_', 'DMSAN_', 'LD_'))}
env['QDMSAN_HOST_LOG'] = str(work / 'target.log')
checks = []

def run(command, **kw):
    return subprocess.run(list(map(str, command)), env=kw.pop('env', env),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=kw.pop('timeout', 20), **kw)

def check(name, condition, detail=None):
    checks.append({'name': name, 'passed': bool(condition), 'detail': detail})
    (work / 'results.json').write_text(json.dumps(checks, indent=2))
    if not condition:
        raise AssertionError(f'{name}: {detail}')
    print(f'PASS {name}', flush=True)

def compile_c(name, source, extra=()):
    path = work / f'{name}.c'
    path.write_text(source)
    binary = work / name
    result = run([os.environ.get('CC', 'cc'), '-D_GNU_SOURCE', '-g', '-O0', path, '-o', binary, *extra])
    check(f'build {name}', result.returncode == 0, result.stderr.decode())
    return binary

probe = compile_c('probe', r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
int main(int argc, char **argv) {
  FILE *in = argc > 1 && strcmp(argv[1], "sleep") ? fopen(argv[1], "rb") : stdin;
  if (!in) return 9;
  unsigned n = 0, sum = 0;
  int c;
  while ((c = fgetc(in)) != EOF) { ++n; sum += (unsigned char)c; }
  const char *(*marker)(void) = dlsym(RTLD_DEFAULT, "host_marker");
  const char *(*extra)(void) = dlsym(RTLD_DEFAULT, "host_extra");
  FILE *out = fopen(getenv("QDMSAN_HOST_LOG"), "a");
  if (!out) return 10;
  fprintf(out, "%u %u %s %s\n", n, sum,
          marker ? marker() : "none", extra ? extra() : "none");
  fclose(out);
  if (argc > 1 && !strcmp(argv[1], "sleep")) sleep(30);
  return 0;
}
''', ['-ldl'])

base = [args.diff.resolve(), '-q', args.qemu.resolve(), '-l', args.runtime.resolve(), '-t', '1000']
data = b'delayed-pipe\x00chunks\n'
input_file = work / 'input.bin'
input_file.write_bytes(data)
log = Path(env['QDMSAN_HOST_LOG'])

def reset_log():
    log.unlink(missing_ok=True)

def rows():
    return log.read_text().splitlines() if log.exists() else []

def check_input(name, command, input_data=None, chunks=None, count=2):
    reset_log()
    if chunks is None:
        result = run(command, input=input_data)
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
    else:
        child = subprocess.Popen(list(map(str, command)), env=env, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for delay, chunk in chunks:
            time.sleep(delay)
            child.stdin.write(chunk)
            child.stdin.flush()
        child.stdin.close()
        child.stdin = None
        stdout, stderr = child.communicate(timeout=20)
        rc = child.returncode
    expected_data = b''.join(c for _, c in chunks) if chunks is not None else input_data
    if expected_data is None:
        expected_data = data
    expected = f'{len(expected_data)} {sum(expected_data)} none none'
    check(name, rc == 0 and rows() == [expected] * count,
          {'rc': rc, 'rows': rows(), 'out': stdout.decode(), 'err': stderr.decode()})
    return stdout.decode()

check_input('file stdin snapshot', [*base, '-i', input_file, '--', probe])
check_input('file @@ snapshot', [*base, '-i', input_file, '--', probe, '@@'])
check_input('immediate pipe', [*base, '--', probe], input_data=data)
check_input('delayed pipe', [*base, '--', probe], chunks=[(0.3, data)])
check_input('chunked pipe', [*base, '--', probe], chunks=[(0.1, data[:4]), (0.2, data[4:])])
out = check_input('empty EOF', [*base, '--', probe], input_data=b'')
check('consumption oracle metadata', 'oracle=consumption' in out)
out = check_input('state oracle three runs', [*base, '-S', '--', probe], input_data=data, count=3)
check('state oracle metadata', 'oracle=state' in out)

explicit_dir = work / 'explicit'
inherited_dir = work / 'inherited'
explicit_dir.mkdir(exist_ok=True)
inherited_dir.mkdir(exist_ok=True)
explicit = compile_c('explicit/libqdmsan.so', 'const char *host_marker(void) { return "explicit"; }', ['-shared', '-fPIC'])
inherited = compile_c('inherited/libqdmsan.so', 'const char *host_marker(void) { return "inherited"; }', ['-shared', '-fPIC'])
other = compile_c('not-libqdmsan.so-helper.so', 'const char *host_extra(void) { return "other"; }', ['-shared', '-fPIC'])
link = work / 'same-runtime.so'
link.unlink(missing_ok=True)
link.symlink_to(explicit)
for name, preload, expected_rc, marker in [
    ('none', '', 0, 'none'), ('same', str(explicit), 0, 'none'),
    ('same symlink', str(link), 0, 'none'), ('conflict', str(inherited), 5, None),
    ('other library with misleading name', str(other), 0, 'other'),
    ('same and other library', f'{other} {explicit}', 0, 'other')]:
    reset_log()
    case_env = dict(env, AFL_PRELOAD=preload)
    result = run([args.diff, '-q', args.qemu, '-l', explicit, '--', probe], input=b'', env=case_env)
    okay = result.returncode == expected_rc
    if expected_rc == 0:
        okay &= rows() == [f'0 0 explicit {marker}'] * 2
    else:
        okay &= not rows() and b'conflicts with selected runtime' in result.stderr
    check(f'preload {name}', okay,
          {'rc': result.returncode, 'rows': rows(), 'err': result.stderr.decode()})

for option, value in [('-t', '0'), ('-t', '-1'), ('-t', '536870912'),
                      ('-C', '-1'), ('-C', '1001'), ('-C', '1x'),
                      ('-R', '-1'), ('-R', '4294967296'), ('-R', '1.5'),
                      ('-t', ' 20'), ('-C', '+1'), ('-R', '18446744073709551616')]:
    result = run([args.diff, option, value, '--', probe], input=b'')
    check(f'numeric reject {option}={value}', result.returncode == 5 and b'integer' in result.stderr)
for option, value in [('-t', '536870911'), ('-C', '0'), ('-R', '4294967295'), ('-R', '0')]:
    result = run([*base, option, value, '--', probe], input=b'')
    check(f'numeric accept {option}={value}', result.returncode == 0, result.stderr.decode())
result = run([*base, '--', probe], input=b'', env=dict(env, AFL_DMSAN_CONFIRM_RUNS='-1'))
check('numeric reject environment confirmation', result.returncode == 5)
result = run([*base, '-m', 'full', '--', probe], input=b'', env=dict(env, AFL_QDMSAN_FULL_SIZE='-1'))
check('numeric reject full-size environment', result.returncode == 5)

# Compile the actual static resolver, then give it hostile and long argv paths.
resolver = compile_c('resolver', r'''
#define main qdmsan_diff_cli_main
#include "qdmsan_diff.c"
#undef main
int main(int argc, char **argv) {
  char output[1024];
  if (argc != 2 || !resolve_addr(argv[1], 0x1234, output, sizeof(output))) return 1;
  puts(output);
  return 0;
}
''', ['-I', ROOT / 'utils/qdmsan-diff', '-I', ROOT / 'include',
       '-DAFL_PATH="/usr/local/lib/afl"', '-DBIN_PATH="/usr/local/bin"',
       '-DDOC_PATH="/usr/local/share/doc/afl"', *[ROOT / 'src' / f for f in
       ['afl-common.c', 'afl-forkserver.c', 'afl-performance.c', 'afl-sharedmem.c']], '-ldl'])
tools = work / 'symbolizer-tools'
tools.mkdir(exist_ok=True)
for name in ['llvm-addr2line', 'addr2line']:
    script = tools / name
    script.write_text('#!/usr/bin/python3\nimport json, os, sys\n'
                      'with open(os.environ["SYMBOL_ARGV"], "a") as f: f.write(json.dumps(sys.argv[1:]) + "\\n")\n'
                      'if os.environ.get("SYMBOL_FAIL") and "llvm" in sys.argv[0]: sys.exit(1)\n'
                      'print("host_function\\nhost_file.c:7")\n')
    script.chmod(0o755)
for name, target, fallback in [
    ('spaces quotes unicode', "a b/quo'te/中文", False),
    ('shell metacharacters', "x';touch HOST_SHELL_EXECUTED;echo '", False),
    ('long target path', 'segment/' * 200 + 'target', False),
    ('fallback', "a'quoted target", True)]:
    argv_log = work / 'symbol-argv.jsonl'
    argv_log.unlink(missing_ok=True)
    result = run([resolver, target], cwd=work,
                 env=dict(env, PATH=f'{tools}:{env["PATH"]}', SYMBOL_ARGV=str(argv_log),
                          SYMBOL_FAIL='1' if fallback else ''))
    seen = [json.loads(x) for x in argv_log.read_text().splitlines()]
    check(f'symbolizer {name}', result.returncode == 0 and
          seen == [['-f', '-C', '-e', target, '0x1234']] * (2 if fallback else 1)
          and not (work / 'HOST_SHELL_EXECUTED').exists(), result.stderr.decode())

# Check heap-plane settings in the suite's actual runner.
suite = (ROOT / 'test_qdmsan/run_qdmsan_suite.sh').read_text()
run_case = suite[suite.index('run_case() {'):suite.index('should_run_row() {')]
fake_diff = work / 'fake-diff'
fake_diff.write_text('#!/usr/bin/env python3\nimport json, os\n'
                     'with open(os.environ["SUITE_ENV_LOG"], "a") as f:\n'
                     ' f.write(json.dumps({k:os.environ.get(k) for k in ["AFL_QDMSAN_COMPAT_STUBS", "AFL_QDMSAN_HEAP_PLANES"]})+"\\n")\n')
fake_diff.chmod(0o755)
suite_log = work / 'suite-env.jsonl'
suite_log.unlink(missing_ok=True)
script = work / 'suite-probe.sh'
script.write_text('set -euo pipefail\n' + run_case + '\n'
                  f'QDMSAN_DIFF={shlex.quote(str(fake_diff))}\n'
                  'QDMSAN_CASE_TIMEOUT=5s\nQDMSAN_DIFF_TIMEOUT_MS=1000\n'
                  + ''.join(f'run_case {origin} ignored {shlex.quote(str(work / (origin + kind)))} fast raw {kind}\n'
                            for origin in ['local'] for kind in ['control', 'heap-oob']))
result = run(['bash', script], env=dict(env, SUITE_ENV_LOG=str(suite_log), AFL_QDMSAN_HEAP_PLANES='inherited'))
seen = [json.loads(x) for x in suite_log.read_text().splitlines()]
check('suite heap/nonheap environment ordering', result.returncode == 0 and seen == [
    {'AFL_QDMSAN_COMPAT_STUBS': None, 'AFL_QDMSAN_HEAP_PLANES': None},
    {'AFL_QDMSAN_COMPAT_STUBS': None, 'AFL_QDMSAN_HEAP_PLANES': '1'}], result.stderr.decode())

# A blocked input read and an active child both terminate promptly and cleanly.
for name, command, pending_input in [
    ('pipe snapshot', [*base, '--', probe], True),
    ('running target', [*base, '-t', '10000', '-i', input_file, '--', probe, 'sleep'], False)]:
    reset_log()
    child = subprocess.Popen(list(map(str, command)), env=env, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not pending_input:
        deadline = time.monotonic() + 10
        while not rows() and time.monotonic() < deadline:
            time.sleep(0.02)
        check('signal target started', bool(rows()))
    else:
        time.sleep(0.1)
    child.send_signal(signal.SIGTERM)
    stdout, stderr = child.communicate(timeout=3)
    segments = Path('/proc/sysvipc/shm').read_text().splitlines()[1:]
    owned = [line for line in segments if int(line.split()[4]) == child.pid]
    check(f'signal shared-memory cleanup {name}', not owned, owned)
    check(f'signal cleanup {name}', child.returncode == 128 + signal.SIGTERM,
          {'rc': child.returncode, 'out': stdout.decode(), 'err': stderr.decode()})

# Force the previously racy window: a forkserver child has started but has
# not sent its first protocol word. SIGTERM must remain cancellation, not an
# initialization crash, and must wake a long startup wait immediately.
startup = compile_c('startup-blocker', r'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
  FILE *f = fopen(getenv("QDMSAN_START_MARKER"), "w");
  if (!f) return 12;
  fputs("ready", f);
  fclose(f);
  for (;;) pause();
}
''')
for attempt in range(5):
    marker = work / f'startup-ready-{attempt}'
    marker.unlink(missing_ok=True)
    child = subprocess.Popen([str(args.diff), '-q', str(startup), '-l', str(args.runtime),
                              '-t', '10000', '-i', str(input_file), '--', str(probe)],
                             env=dict(env, QDMSAN_START_MARKER=str(marker)),
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.005)
    check(f'signal startup child ready {attempt}', marker.exists())
    child.send_signal(signal.SIGTERM)
    stdout, stderr = child.communicate(timeout=3)
    segments = Path('/proc/sysvipc/shm').read_text().splitlines()[1:]
    owned = [line for line in segments if int(line.split()[4]) == child.pid]
    check(f'signal startup cancellation {attempt}', child.returncode == 143 and
          not owned and b'PROGRAM ABORT' not in stdout + stderr,
          {'rc': child.returncode, 'segments': owned,
           'out': stdout.decode(), 'err': stderr.decode()})

print(f'{len(checks)} checks passed; artifacts: {work}')
