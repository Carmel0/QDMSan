#!/usr/bin/env python3
"""Synthetic release regressions; all outputs go to the requested directory.

Default joined-thread classifications may be nondet because of syscall noise.
The separate nosys profile is diagnostic, not a recommended detector setting.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qdmsan-diff", required=True, type=Path)
    parser.add_argument("--qemu", required=True, type=Path)
    parser.add_argument("--preload", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    for field in ("qdmsan_diff", "qemu", "preload", "out_dir"):
        setattr(args, field, getattr(args, field).resolve())
    args.out_dir.mkdir(parents=True, exist_ok=True)
    src = Path(__file__).resolve().parent
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("AFL_", "__AFL_", "__DMS", "QDMSAN_"))
           and k not in ("LD_PRELOAD", "QEMU_SET_ENV", "QEMU_UNSET_ENV")}
    cc = shlex.split(os.environ.get("CC", "cc"))
    for name in ("worker_bad", "worker_good", "api", "realloc"):
        source = "worker" if name.startswith("worker_") else name
        command = cc + ["-O2", "-g", "-fno-pie", "-no-pie", "-pthread"]
        if name == "worker_good":
            command += ["-DDEFINED"]
        command += [str(src / ("runtime_release_" + source + ".c")),
                    "-o", str(args.out_dir / name)]
        subprocess.run(command, check=True, env=env)

    rows = []
    failures = []

    def run(label, command, child_env):
        result = subprocess.run(command, env=child_env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=20)
        (args.out_dir / (label + ".log")).write_text(result.stdout)
        return result

    def require(condition, message):
        if not condition:
            failures.append(message)

    # Compare return/errno probes against native libc and QEMU+preload. The
    # preload's deterministic APIs require QEMU hypercalls, so standalone
    # LD_PRELOAD is used only for the allocator callback regression.
    for target in ("api", "realloc"):
        command = [str(args.out_dir / target)]
        native = run(target + "_native", command, env)
        if target == "realloc":
            preload_env = dict(env, LD_PRELOAD=str(args.preload))
            preload = run(target + "_preload", command, preload_env)
            require(preload.returncode == 0, "realloc/preload failed")
        qemu_env = dict(env, AFL_USE_QDMSAN="1")
        qemu = run(target + "_qemu", [str(args.qemu), "-E",
                   "LD_PRELOAD=" + str(args.preload)] + command, qemu_env)
        for profile, result in (("native", native), ("qemu", qemu)):
            require(result.returncode == 0, f"{target}/{profile}: exit {result.returncode}")
        require(native.stdout == qemu.stdout,
                target + ": return/errno output differs from libc")
    deterministic = []
    for repeat in range(2):
        result = run(f"api_deterministic_{repeat}", [str(args.qemu), "-E",
                     "LD_PRELOAD=" + str(args.preload), str(args.out_dir / "api"),
                     "deterministic"], dict(env, AFL_USE_QDMSAN="1"))
        require(result.returncode == 0, "deterministic API probe failed")
        deterministic.append(result.stdout)
    require(deterministic[0] == deterministic[1],
            "valid random/time APIs changed across identical runs")

    for profile in ("default", "nosys", "compat", "compat_nosys"):
        run_env = env.copy()
        if "nosys" in profile:
            run_env["AFL_QDMSAN_CHECK_SYSCALLS"] = "0"
        if "compat" in profile:
            run_env["AFL_QDMSAN_PAPER_COMPAT"] = "1"
        for good in (False, True):
            for threads in (1, 8):
                exit_modes = ["live", "join", "fork", "busy", "running_fork"]
                if profile == "nosys":
                    exit_modes += ["exit_worker", "pthread_exit"]
                for exit_mode in exit_modes:
                    pair = []
                    for count in (0, 1):
                        label = f"{profile}_{good}_{threads}_{exit_mode}_{count}"
                        command = [str(args.qdmsan_diff), "-q", str(args.qemu),
                                   "-l", str(args.preload), "-v", "-t", "5000", "--",
                                   str(args.out_dir / ("worker_good" if good else "worker_bad")),
                                   exit_mode, str(count), str(threads)]
                        result = run(label, command, run_env)
                        count_match = re.search(r"run1: UUM=\([^,]+,[^,]+,(\d+)\)", result.stdout)
                        decision = re.search(r"^\[(\w+)\]", result.stdout, re.M)
                        runs = re.search(r"check=raw runs=(\d+)", result.stdout)
                        row = dict(label=label, profile=profile, good=good,
                                   threads=threads, exit_mode=exit_mode, count=count,
                                   returncode=result.returncode,
                                   events=int(count_match[1]) if count_match else None,
                                   decision=decision[1] if decision else None,
                                   runs=int(runs[1]) if runs else None)
                        rows.append(row)
                        pair.append(row)
                        require(result.returncode in (0, 1, 2), label + ": abnormal exit")
                        require("abi=0x0000000000000000" in result.stdout,
                                label + ": default heap ABI changed")
                        # Joined syscall scheduling is an independent source
                        # of noise. Observe it; do not call nondet a bug result.
                        if exit_mode != "join" or "nosys" in profile:
                            detects = ("compat" not in profile or exit_mode == "join")
                            expected = "bug" if count and not good and detects else "clean"
                            require(row["decision"] == expected,
                                    label + ": expected " + expected)
                            require(row["runs"] == (3 if expected == "bug" else 2),
                                    label + ": unexpected replay count")
                    if None not in (pair[0]["events"], pair[1]["events"]):
                        delta = pair[1]["events"] - pair[0]["events"]
                        expected_delta = (0 if "compat" in profile and exit_mode != "join"
                                          else 192 * threads)
                        if exit_mode != "join" or "nosys" in profile:
                            require(delta == expected_delta,
                                    f"{label}: event delta {delta}, expected {expected_delta}")
                    else:
                        failures.append(label + ": missing fast signature")

    # Full mode remains an independent diagnostic: its executed-event delta
    # survives even when compatibility mode deliberately omits live TLS.
    for compat in (False, True):
        run_env = env.copy()
        if compat:
            run_env["AFL_QDMSAN_PAPER_COMPAT"] = "1"
        full_counts = []
        for count in (0, 1):
            label = f"full_compat{compat}_{count}"
            result = run(label, [str(args.qdmsan_diff), "-q", str(args.qemu),
                         "-l", str(args.preload), "-m", "full", "-v", "-t", "5000", "--",
                         str(args.out_dir / "worker_bad"), "live", str(count), "1"], run_env)
            match = re.search(r"full: total=(\d+) overflow=0", result.stdout)
            require(match is not None, label + ": full diagnostics missing")
            full_counts.append(int(match[1]) if match else 0)
        require(full_counts[1] - full_counts[0] == 192,
                f"full compat={compat}: executed-event delta differs")

    (args.out_dir / "summary.json").write_text(json.dumps(
        {"thread_runs": rows, "failures": failures}, indent=2) + "\n")
    for failure in failures:
        print("FAIL:", failure)
    print(f"Runtime regressions: {len(rows)} thread runs, API/allocator and full checks; "
          f"{len(failures)} failures. Logs: {args.out_dir}")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
