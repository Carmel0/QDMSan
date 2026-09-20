#!/usr/bin/env python3
"""Build a vulnerable or fixed target with an uninstrumented file driver."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
VERSIONS = {
    ('cyclonedds', 'vulnerable'): ('https://github.com/eclipse-cyclonedds/cyclonedds.git', 'c7b1e48a5bdbcedf16e7500594f335905ed76fbb'),
    ('cyclonedds', 'fixed'): ('https://github.com/eclipse-cyclonedds/cyclonedds.git', '61b007559d821604025917d1721bc740b6cb832d'),
    ('glog', 'vulnerable'): ('https://github.com/google/glog.git', '53d58e4531c7c90f71ddab503d915e027432447a'),
    # glog development moved to ng-log, where this bug was fixed.
    ('glog', 'fixed'): ('https://github.com/ng-log/ng-log.git', 'ece82e12f85a5ec60b6153382ce81af292d5c78e'),
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('case', choices=['cyclonedds', 'glog'])
    p.add_argument('version', choices=['vulnerable', 'fixed'])
    p.add_argument('--work', type=Path, required=True, help='new directory; existing directories are refused')
    p.add_argument('--cc', default='clang')
    p.add_argument('--cxx', default='clang++')
    p.add_argument('--jobs', type=int, default=2)
    args = p.parse_args()
    if args.jobs < 1:
        p.error('--jobs must be positive')
    for tool in ('git', 'cmake', args.cc, args.cxx):
        if not shutil.which(tool):
            p.error('missing build tool: ' + tool)
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    src, build = work / 'src', work / 'build'
    url, rev = VERSIONS[args.case, args.version]
    e = os.environ.copy()
    for k in list(e):
        if k.startswith(('AFL_', '__DMS', 'QDMSAN_')) or k == 'LD_PRELOAD':
            e.pop(k)
    flags = '-O2 -gdwarf-4 -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1'
    e.update(CC=args.cc, CXX=args.cxx, CFLAGS=flags, CXXFLAGS=flags,
             LIB_FUZZING_ENGINE=str(work / 'standalone_driver.o'))

    def run(cmd):
        subprocess.run(cmd, cwd=work, env=e, check=True)

    run(['git', 'init', str(src)])
    run(['git', '-C', str(src), 'remote', 'add', 'origin', url])
    run(['git', '-C', str(src), 'fetch', '--depth', '1', 'origin', rev])
    run(['git', '-C', str(src), 'checkout', '--detach', 'FETCH_HEAD'])
    actual = subprocess.check_output(['git', '-C', str(src), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != rev:
        raise SystemExit('revision mismatch')
    run([args.cc, *flags.split(), '-c', str(HERE / 'standalone_driver.c'), '-o', str(work / 'standalone_driver.o')])
    options = ['-DBUILD_SHARED_LIBS=OFF', '-DBUILD_TESTING=OFF']
    if args.case == 'glog':
        target = 'fuzz_demangle'
        options += ['-DWITH_FUZZING=ossfuzz']
    else:
        target = 'fuzz_handle_rtps_message'
        # Build only this upstream harness, without handshake/protobuf/idlc fuzzers.
        path = src / 'fuzz/CMakeLists.txt'
        text = path.read_text()
        text = re.sub(r'^add_subdirectory\((?!fuzz_handle_rtps_message\))[^\n]+$', '', text, flags=re.M)
        path.write_text('enable_language(CXX)\n' + text)
        options += ['-DBUILD_IDLC=ON', '-DEXPORT_ALL_SYMBOLS=ON', '-DBUILD_EXAMPLES=OFF',
                    '-DENABLE_SECURITY=ON', '-DENABLE_SSL=ON', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON']
    run(['cmake', '-S', str(src), '-B', str(build), *options])
    run(['cmake', '--build', str(build), '--target', target, '-j', str(args.jobs)])
    matches = [x for x in build.rglob(target) if x.is_file() and os.access(x, os.X_OK)]
    if len(matches) != 1:
        raise SystemExit(f'expected one target binary, found {matches}')
    result = {'case': args.case, 'version': args.version, 'repository': url, 'revision': actual,
              'target': str(matches[0].relative_to(work)),
              'target_sha256': hashlib.sha256(matches[0].read_bytes()).hexdigest(),
              'cc': args.cc, 'cxx': args.cxx, 'flags': flags, 'cmake_options': options}
    (work / 'build.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
