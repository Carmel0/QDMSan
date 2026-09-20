#!/usr/bin/env python3
"""Replay a fixed real-world bug with QDMSan or Memcheck."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
INPUTS = {'cyclonedds': '4c0638e7dffa8eb13ac4b329e66d5642d30eca8d2448554cccb7b865da935dc6',
          'glog': '6c0756e151aed697bae9cd5583b46d56116a6892b0fdddcef5678ba9ed2bb9ab'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('case', choices=INPUTS)
    p.add_argument('--target', type=Path, required=True)
    p.add_argument('--tool', choices=['qdmsan', 'memcheck'], default='qdmsan')
    p.add_argument('--qd-diff', type=Path)
    p.add_argument('--qemu', type=Path)
    p.add_argument('--runtime', type=Path)
    p.add_argument('--memcheck', default='valgrind')
    args = p.parse_args()
    sample = HERE / args.case / 'input.bin'
    if hashlib.sha256(sample.read_bytes()).hexdigest() != INPUTS[args.case]:
        raise SystemExit('input hash mismatch')
    e = os.environ.copy()
    for k in list(e):
        if k.startswith(('AFL_', '__AFL_', '__DMS', 'QDMSAN_')) or k in ('LD_PRELOAD', 'QEMU_SET_ENV', 'QEMU_UNSET_ENV'):
            e.pop(k)
    e['AFL_QDMSAN_COMPAT_STUBS'] = '0'
    if args.case == 'glog':
        e['AFL_QDMSAN_STACK_MAX'] = '8192'
    if args.tool == 'qdmsan':
        if not all((args.qd_diff, args.qemu, args.runtime)):
            p.error('--qd-diff, --qemu and --runtime are required')
        cmd = [str(args.qd_diff.resolve()), '-q', str(args.qemu.resolve()), '-l', str(args.runtime.resolve()),
               '-m', 'fast', '-c', 'raw', '-t', '10000', '-v', '--']
    else:
        cmd = [args.memcheck, '--tool=memcheck', '--track-origins=yes', '--error-exitcode=99']
    cmd += [str(args.target.resolve()), '--input-file', str(sample)]
    result = subprocess.run(cmd, env=e, timeout=60)
    print(json.dumps({'case': args.case, 'tool': args.tool, 'exit_code': result.returncode,
                      'input_sha256': INPUTS[args.case],
                      'target_sha256': hashlib.sha256(args.target.read_bytes()).hexdigest()}))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
