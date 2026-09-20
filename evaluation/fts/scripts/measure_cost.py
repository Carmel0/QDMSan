#!/usr/bin/env python3
"""Measure standalone detector cost on a fixed corpus.

Each input runs in a fresh process on one selected CPU. The shm variant performs
one QDMSan execution; qd performs the full differential check. The other variants
run plain QEMU, QMSan accurate, or Memcheck on the same ordered inputs.
"""
import argparse, collections, ctypes, json, math, os, resource, shutil, statistics, subprocess, sys, time

IPC_PRIVATE = 0
IPC_CREAT = 0o1000
IPC_RMID = 0
FAST_MAP_BYTES = 1 << 22          # generous: >= sizeof(struct dmsan_fast_map), mapped at offset 0
TIMEOUT_S = 60


def libc():
    c = ctypes.CDLL("libc.so.6", use_errno=True)
    c.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
    c.shmget.restype = ctypes.c_int
    c.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    c.shmat.restype = ctypes.c_void_p
    c.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    c.shmctl.restype = ctypes.c_int
    return c


class Shm:
    """The two segments qdmsan-diff creates before every check."""

    def __init__(self):
        self.c = libc()
        self.fast_id = self.c.shmget(IPC_PRIVATE, FAST_MAP_BYTES, IPC_CREAT | 0o600)
        if self.fast_id < 0:
            raise OSError(ctypes.get_errno(), "shmget fast map failed")
        self.fast_addr = self.c.shmat(self.fast_id, None, 0)
        if self.fast_addr in (None, ctypes.c_void_p(-1).value, 2 ** 64 - 1):
            raise OSError(ctypes.get_errno(), "shmat fast map failed")
        self.poison_id = self.c.shmget(IPC_PRIVATE, 1, IPC_CREAT | 0o600)
        if self.poison_id < 0:
            raise OSError(ctypes.get_errno(), "shmget poison byte failed")
        self.poison_addr = self.c.shmat(self.poison_id, None, 0)
        # Baseline selector for the first run.
        ctypes.c_uint8.from_address(self.poison_addr).value = 0x11

    def zero(self):
        ctypes.memset(self.fast_addr, 0, FAST_MAP_BYTES)

    def words(self, n=8):
        return [ctypes.c_uint64.from_address(self.fast_addr + 8 * i).value for i in range(n)]

    def close(self):
        self.c.shmctl(self.fast_id, IPC_RMID, None)
        self.c.shmctl(self.poison_id, IPC_RMID, None)


def env_for(bundle, variant, shm=None):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("AFL_", "QMSAN", "QASAN", "DMSAN", "__AFL", "QEMU_",
                                "__DMSAN", "__DMSPVAL", "QDMSAN_EVAL_", "QDE_"))
           and k not in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONHOME", "PYTHONPATH")}
    libdir = os.path.join(bundle, "env", "lib")
    if os.path.isdir(libdir):
        env["LD_LIBRARY_PATH"] = libdir
        env["QEMU_UNSET_ENV"] = "LD_LIBRARY_PATH,QEMU_UNSET_ENV"
    if variant == "plain":
        return env
    if variant == "qmsan":
        return env
    if variant == "memcheck":
        env.pop("LD_LIBRARY_PATH", None)
        env.pop("QEMU_UNSET_ENV", None)
        return env
    if variant == "qd":
        env["AFL_QDMSAN_COMPAT_STUBS"] = "0"
        return env
    env["AFL_USE_QDMSAN"] = "1"
    env["AFL_QDMSAN_CHECK"] = "raw"
    env["AFL_QDMSAN_COMPAT_STUBS"] = "0"
    if variant == "shm":
        # Match the shared-memory and selector setup of qdmsan-diff.
        env["__DMSAN_FAST_SHM_ID"] = str(shm.fast_id)
        env["__DMSPVAL_SHM_ID"] = str(shm.poison_id)
        env["AFL_QDMSAN_MODE"] = "fast"
        env["AFL_MAP_SIZE"] = "65536"
        env["QEMU_RAND_SEED"] = "42"
        env["AFL_PRELOAD"] = os.path.join(bundle, "qdmsan", "bin", "libqdmsan.so")
    return env


def child_setup():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.setsid()


def cmd_for(bundle, t, inp, core, variant="shm"):
    pre = ["taskset", "-c", str(core), "timeout", "-k", "5", str(TIMEOUT_S)]
    if variant == "plain":
        return pre + [os.path.join(bundle, "qdmsan", "bin", "afl-qemu-trace"), "--",
                      os.path.join(bundle, "targets", t, "fuzz_target"), inp]
    if variant == "qd":
        qb = os.path.join(bundle, "qdmsan", "bin")
        return ["taskset", "-c", str(core), "timeout", "-k", "5", "180",
                os.path.join(qb, "qdmsan-diff"), "-q", os.path.join(qb, "afl-qemu-trace"),
                "-l", os.path.join(qb, "libqdmsan.so"), "-m", "fast", "-c", "raw",
                "-t", "5000", "-v", "-i", inp, "--",
                os.path.join(bundle, "targets", t, "fuzz_target"), "@@"]
    if variant == "qmsan":
        return ["taskset", "-c", str(core), "timeout", "-k", "5", "120",
                os.path.join(bundle, "baselines", "qmsan-accurate", "qmsan"),
                os.path.join(bundle, "targets", t, "fuzz_target"), inp]
    if variant == "memcheck":
        return ["taskset", "-c", str(core), "timeout", "-k", "5", "300",
                os.path.realpath(os.path.join(bundle, "env", "valgrind", "valgrind")), "--tool=memcheck",
                "--error-exitcode=99", "--leak-check=no", "--track-origins=no",
                os.path.join(bundle, "targets", t, "fuzz_target.memcheck"), inp]
    return pre + [os.path.join(bundle, "qdmsan", "bin", "afl-qemu-trace"), "--",
                  os.path.join(bundle, "targets", t, "fuzz_target"), inp]


def one_arm(bundle, t, inputs, out_dir, core, variant, shm):
    os.makedirs(out_dir, exist_ok=True)
    cwd = os.path.join(out_dir, "cwd")
    shutil.rmtree(cwd, ignore_errors=True)
    os.makedirs(cwd)
    with open(os.path.join(bundle, "targets", t, "target.json")) as f:
        rt = json.load(f).get("runtime_dir")
    if rt:
        shutil.copytree(os.path.join(bundle, "targets", t, rt), os.path.join(cwd, rt))
    env = env_for(bundle, variant, shm)
    rcs = collections.Counter()
    t0 = time.time()
    with open(os.path.join(out_dir, "arm.log"), "wb") as lf:
        for inp in inputs:
            if shm is not None:
                shm.zero()
            p = subprocess.run(cmd_for(bundle, t, inp, core, variant), cwd=cwd, env=env,
                               stdin=subprocess.DEVNULL, stdout=lf, stderr=lf,
                               preexec_fn=child_setup)
            rcs[p.returncode] += 1
    wall = time.time() - t0
    shutil.rmtree(cwd, ignore_errors=True)
    rec = {"target": t, "arm": variant, "core": core, "n_inputs": len(inputs),
           "wall_s": round(wall, 3), "per_input_s": round(wall / len(inputs), 4),
           "inputs_per_s": round(len(inputs) / wall, 3),
           "rc_counts": {str(k): v for k, v in sorted(rcs.items())},
           "timeouts": rcs[124] + rcs[137]}
    with open(os.path.join(out_dir, "result.json"), "w") as f:
        json.dump(rec, f, indent=1)
    return rec


def verify(bundle, t, inputs, core, qd_log, out, limit=20):
    """Run <limit> inputs one at a time with the shm attached and compare the number of
    recorded events with qdmsan-diff's own `run1: UUM=(a,b,N)` for the same inputs."""
    want = []
    with open(qd_log, "r", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s.startswith("run1: UUM=("):
                trip = s[len("run1: UUM=("):].split(")")[0].split(",")
                # The historical replay helper prints the first-run signature twice;
                # keep one per input.
                if not want or want[-1] != trip:
                    want.append(trip)
    shm = Shm()
    env = env_for(bundle, "shm", shm)
    cwd = os.path.join(out, "_verify_cwd_%s" % t)
    shutil.rmtree(cwd, ignore_errors=True)
    os.makedirs(cwd)
    with open(os.path.join(bundle, "targets", t, "target.json")) as f:
        rt = json.load(f).get("runtime_dir")
    if rt:
        shutil.copytree(os.path.join(bundle, "targets", t, rt), os.path.join(cwd, rt))
    out = []
    for i, inp in enumerate(inputs[:limit]):
        shm.zero()
        subprocess.run(cmd_for(bundle, t, inp, core, "shm"), cwd=cwd, env=env,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, preexec_fn=child_setup)
        w = shm.words(8)
        ref = want[i] if i < len(want) else None
        out.append({"idx": i, "input": os.path.basename(inp),
                    "sum": "0x%016x" % w[0], "rotl": "0x%016x" % w[1],
                    "mul": "0x%016x" % w[2], "count": w[3],
                    "qdmsan_diff_run1": ref})
    shutil.rmtree(cwd, ignore_errors=True)
    shm.close()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--corpus", required=True)

    ap.add_argument("--out", required=True)
    ap.add_argument("--targets", required=True)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--core", type=int, required=True)
    ap.add_argument("--variant",
                    choices=("shm", "plain", "qd", "qmsan", "memcheck"),
                    required=True)
    ap.add_argument("--inputs", type=int, default=0, help="0 = all files in each target corpus directory")
    ap.add_argument("--verify", metavar="QD_ARM_LOG",
                    help="verification mode: compare the fast map against this qd arm.log")
    ap.add_argument("--verify-limit", type=int, default=20)
    a = ap.parse_args()
    targets = [t for t in a.targets.split(",") if t]
    os.makedirs(a.out, exist_ok=True)

    if a.verify:
        t = targets[0]
        names = sorted(n for n in os.listdir(os.path.join(a.corpus, t))
                       if os.path.isfile(os.path.join(a.corpus, t, n)))
        inputs = [os.path.abspath(os.path.join(a.corpus, t, n)) for n in names]
        res = verify(a.bundle, t, inputs, a.core, a.verify, a.out, a.verify_limit)
        out_path = os.path.join(a.out, "verify_%s.json" % t)
        with open(out_path, "w") as f:
            json.dump({"target": t, "qd_arm_log": a.verify, "core": a.core, "rows": res}, f, indent=1)
        print(json.dumps(res, indent=1))
        print("wrote", out_path)
        return

    shm = Shm() if a.variant == "shm" else None
    runs_name = "cost_%s.json" % a.variant
    rows = []
    try:
        for t in targets:
            names = sorted(n for n in os.listdir(os.path.join(a.corpus, t))
                       if os.path.isfile(os.path.join(a.corpus, t, n)))
            if a.inputs:
                names = names[:a.inputs]
            inputs = [os.path.abspath(os.path.join(a.corpus, t, n)) for n in names]
            for rep in range(1, a.reps + 1):
                d = os.path.join(a.out, "runs", t, a.variant, "r%d" % rep)
                r = one_arm(a.bundle, t, inputs, d, a.core, a.variant, shm)
                r["rep"] = rep
                rows.append(r)
                print("  %-22s %-12s rep%d core%2d n=%d wall=%.1fs per_input=%.4fs rc=%s" %
                      (t, r["arm"], rep, r["core"], r["n_inputs"], r["wall_s"],
                       r["per_input_s"], r["rc_counts"]), flush=True)
                with open(os.path.join(a.out, runs_name), "w") as f:
                    json.dump(rows, f, indent=1)
    finally:
        if shm is not None:
            shm.close()

    with open(os.path.join(a.out, runs_name), "w") as f:
        json.dump(rows, f, indent=1)

    base = {}
    seq = os.path.join(a.out, "cost_plain.json")
    if os.path.exists(seq):
        for r in json.load(open(seq)):
            if r["arm"] == "plain":
                base.setdefault(r["target"], []).append(r["wall_s"])
    print("\n%-22s %4s %10s %10s %11s %8s" % ("target", "n", "med_s", "s/input", "plain_med_s", "xplain"))
    ratios = []
    for t in targets:
        v = [r["wall_s"] for r in rows if r["target"] == t]
        if not v:
            continue
        med = statistics.median(v)
        n = [r for r in rows if r["target"] == t][0]["n_inputs"]
        p = statistics.median(base[t]) if t in base else None
        rel = med / p if p else None
        if rel:
            ratios.append(rel)
        print("%-22s %4d %10.2f %10.4f %11s %8s" %
              (t, len(v), med, med / n, "%.2f" % p if p else "-", "%.2f" % rel if rel else "-"))
    if ratios:
        g = math.exp(sum(math.log(x) for x in ratios) / len(ratios))
        print("\ngeometric mean over %d targets: %.2fx plain  (min %.2f, max %.2f)" %
              (len(ratios), g, min(ratios), max(ratios)))
    print("\nwrote", os.path.join(a.out, runs_name))


if __name__ == "__main__":
    main()
