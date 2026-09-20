#!/usr/bin/env python3
"""Portable build/replay runner for public Juliet and the 13 synthetic pairs."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def juliet_cases():
    with (ROOT / 'manifests/juliet.tsv').open() as f:
        for row in csv.DictReader(f, delimiter='\t'):
            for variant in ('bad', 'good'):
                sources = []
                for src in row['sources'].split(','):
                    if not src.startswith('src/'):
                        src = 'src/testcases/CWE457_Use_of_Uninitialized_Variable/' + src
                    sources.append(src.format(variant='bad' if variant == 'bad' else 'good1'))
                yield row | {'variant': variant, 'sources_linked': sources}


def env():
    e = os.environ.copy()
    for k in list(e):
        if k.startswith(('AFL_', '__AFL_', '__DMS', 'QDMSAN_')) or k in ('LD_PRELOAD', 'QEMU_SET_ENV', 'QEMU_UNSET_ENV'):
            e.pop(k)
    e.update(LANG='C', LC_ALL='C', AFL_QDMSAN_COMPAT_STUBS='0')
    return e


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(cmd, cwd, timeout=120):
    return subprocess.run(cmd, cwd=cwd, env=env(), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, preexec_fn=no_core)


def classify(tool, rc, text):
    if tool in ('QDMSan', 'QD-State'):
        if rc == 1:
            if tool == 'QD-State':
                return 'REPORT'
            return 'UUM_REPORT' if re.search(r'\[bug\].*confirmed=\S*UUM', text) else 'NONUUM_REPORT'
        return {0: 'CLEAN', 2: 'NONDET', 3: 'CRASH_OR_TIMEOUT', 4: 'CRASH_OR_TIMEOUT', 124: 'CRASH_OR_TIMEOUT'}.get(rc, 'ERROR')
    if tool == 'Memcheck':
        if re.search(r'Conditional jump or move depends on uninitialised|Use of uninitialised value|Syscall param .*uninitialised byte', text):
            return 'UUM_REPORT'
        if rc == 124 or 'Process terminating with default action of signal' in text:
            return 'CRASH_OR_TIMEOUT'
        if re.search(r'ERROR SUMMARY: 0 errors', text):
            return 'CLEAN'
        return 'NONUUM_REPORT' if re.search(r'ERROR SUMMARY: [1-9]', text) else 'ERROR'
    if rc == 89 and re.search(r'^Use of tainted', text, re.M):
        return 'UUM_REPORT'
    if rc < 0 or rc == 124 or 'qemu: uncaught target signal' in text:
        return 'CRASH_OR_TIMEOUT'
    return 'CLEAN' if rc == 0 else 'ERROR'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['build', 'run'])
    p.add_argument('suite', choices=['juliet', 'controls'])
    p.add_argument('--out', type=Path, required=True, help='build/results directory outside the source tree')
    p.add_argument('--juliet-source', type=Path)
    p.add_argument('--cc', default=None)
    p.add_argument('--cxx', default='g++')
    p.add_argument('--tool', choices=['QDMSan', 'QD-State', 'QMSan', 'Memcheck'], default='QDMSan')
    p.add_argument('--qd-diff', type=Path)
    p.add_argument('--qemu', type=Path)
    p.add_argument('--runtime', type=Path)
    p.add_argument('--qmsan', type=Path)
    p.add_argument('--memcheck', default='valgrind')
    p.add_argument('--limit', type=int, default=0, help='smoke only; zero means the full selected suite')
    args = p.parse_args()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.action == 'build':
        records = []
        if args.suite == 'juliet':
            if args.juliet_source is None:
                p.error('--juliet-source is required for a Juliet build')
            sources = list(juliet_cases())
        else:
            sources = [{'case': r['source'][:-2], 'variant': r['role'], 'opt': o, 'group': r['group'], 'source': r['source'], 'sha256': r['sha256']}
                       for r in json.loads((ROOT / 'manifests/controls.json').read_text()) for o in r['optimizations']]
        if args.limit:
            sources = sources[:args.limit]
        for r in sources:
            if args.suite == 'juliet':
                case, opt = r['stem'], 'O0'
                cwd = args.juliet_source.resolve() / r['case_id']
                compiler = args.cxx if r['cc'] == 'g++' else (args.cc or 'gcc')
                flags = ['-I', 'src/testcasesupport', '-DINCLUDEMAIN', '-DOMITGOOD' if r['variant'] == 'bad' else '-DOMITBAD',
                         '-w', '-O0', '-g', '-fno-omit-frame-pointer', '-fno-builtin', '-fno-stack-protector']
                srcs = r['sources_linked']
                group = r['group']
            else:
                case, opt, group = r['case'], r['opt'], r['group']
                cwd = ROOT / 'controls/cases'
                compiler, flags, srcs = args.cc or 'clang-18', ['-' + opt, '-g', '-fno-omit-frame-pointer'], [r['source']]
                if sha(cwd / r['source']) != r['sha256']:
                    raise SystemExit('control source hash mismatch')
            identity = f'{args.suite}/{opt}/{r["variant"]}/{case}'
            target = args.out / 'bin' / identity
            target.parent.mkdir(parents=True, exist_ok=True)
            objdir = args.out / 'obj' / identity
            objdir.mkdir(parents=True, exist_ok=True)
            objects, commands, logs = [], [], []
            for i, src in enumerate(srcs):
                obj = objdir / f'{i}.o'
                cmd = [compiler, *flags, '-c', src, '-o', str(obj)]
                result = run(cmd, cwd)
                commands.append(cmd); logs.append(result.stdout.decode(errors='replace'))
                if result.returncode:
                    raise SystemExit('compile failed:\n' + logs[-1])
                objects.append(str(obj))
            cmd = [compiler, *flags, *objects, '-o', str(target)]
            result = run(cmd, cwd)
            if result.returncode:
                raise SystemExit(result.stdout.decode(errors='replace'))
            records.append({'suite': args.suite, 'case': case, 'variant': r['variant'], 'opt': opt,
                            'group': group, 'included': 'true', 'binary': str(target.relative_to(args.out)), 'binary_sha256': sha(target)})
        (args.out / (args.suite + '-binaries.json')).write_text(json.dumps(records, indent=2) + '\n')
        print(f'Built {len(records)} binaries; no sanitizer instrumentation was used.')
        return
    records = json.loads((args.out / (args.suite + '-binaries.json')).read_text())
    if args.limit:
        records = records[:args.limit]
    if args.tool in ('QDMSan', 'QD-State') and not all((args.qd_diff, args.qemu, args.runtime)):
        p.error('--qd-diff, --qemu, and --runtime are required')
    if args.tool == 'QMSan' and not args.qmsan:
        p.error('--qmsan must name the accurate detector launcher')
    rundir = args.out / 'rundir'
    rundir.mkdir(exist_ok=True)
    rows = []
    for r in records:
        binary = args.out / r['binary']
        if sha(binary) != r['binary_sha256']:
            raise SystemExit('binary hash mismatch')
        if args.tool in ('QDMSan', 'QD-State'):
            cmd = [str(args.qd_diff.resolve()), '-q', str(args.qemu.resolve()), '-l', str(args.runtime.resolve()),
                   '-m', 'fast', '-c', 'raw', '-t', '10000', '-v']
            if args.tool == 'QD-State':
                cmd += ['-S']
            cmd += ['--', str(binary)]
        elif args.tool == 'Memcheck':
            cmd = [args.memcheck, '--tool=memcheck', '--error-exitcode=99', '--track-origins=no', str(binary)]
        else:
            cmd = [str(args.qmsan.resolve()), str(binary)]
        try:
            result = run(cmd, rundir, 60)
            rc, text = result.returncode, result.stdout.decode(errors='replace')
        except subprocess.TimeoutExpired as exc:
            rc, text = 124, (exc.stdout or b'').decode(errors='replace')
        if args.tool in ('QDMSan', 'QD-State'):
            abis = re.findall(r'abi=(0x[0-9a-fA-F]+)', text)
            if not abis or any(int(a, 16) for a in abis):
                raise SystemExit('missing default-plane ABI canary or heap planes unexpectedly enabled')
        log = args.out / 'logs' / args.tool / r['opt'] / r['variant'] / (r['case'] + '.log')
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(text)
        rows.append({k: v for k, v in r.items() if k != 'binary'} | {
            'tool': args.tool, 'category': classify(args.tool, rc, text), 'rc': str(rc)})
    with (args.out / (args.suite + '-' + args.tool + '.tsv')).open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), delimiter='\t')
        writer.writeheader(); writer.writerows(rows)
    print(f'Classified {len(rows)} binaries; results and logs are in {args.out}.')


if __name__ == '__main__':
    main()
