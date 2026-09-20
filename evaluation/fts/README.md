# Cost measurements

The paper compares five configurations on the same inputs over three complete
rounds. Each configuration runs on a separate physical core, concurrently with the
others. The historical corpus contains undisclosed findings and is withheld;
the drivers accept caller-provided targets and inputs.

## Target bundle

Use absolute paths for the bundle, corpus and output directories:

```text
bundle/
  qdmsan/bin/{afl-qemu-trace,qdmsan-diff,libqdmsan.so}
  baselines/qmsan-accurate/qmsan
  env/valgrind/valgrind
  env/lib/                         # optional tool dependencies
  targets/<name>/
    fuzz_target                    # takes one input filename
    fuzz_target.memcheck            # target with Memcheck-readable debug info
    target.json
    runtime/                       # optional files needed at run time
corpus/<name>/<input files>
```

Copy or link QDMSan tools from one build. Link `env/valgrind/valgrind` to the
installed Valgrind executable. Targets must be ordinary binaries that read
their first argument and execute one input. For libFuzzer targets, link a
file-input driver in place of libFuzzer. Baseline versions are listed in
[AE.md](../../AE.md#baselines).

A minimal `target.json` is `{"runtime_dir": null}`. If a target needs working
directory files, put them in `runtime/` and set `"runtime_dir": "runtime"`.
[fts-targets.json](../manifests/fts-targets.json) lists the paper target versions
and configurations. Historical target binaries are not distributed.

## Run three rounds

Set `BUNDLE`, `CORPUS`, and `RESULTS` to absolute paths. In the Bash example
below, replace cores 2–6 with five available physical cores, avoiding sibling
threads of the same core. Keep the same corpus across every variant and round.

```bash
TARGETS=libxml2-v2.9.2,pcre2-10.00,re2-2014-12-09,openssl-1.0.1f,json-2017-02-12,guetzli-2017-3-30
for round in 1 2 3; do
  mkdir -p "$RESULTS/round$round"
  pids=()
  for spec in plain:2:3 shm:3:3 qd:4:3 qmsan:5:3 memcheck:6:1; do
    IFS=: read -r variant core reps <<< "$spec"
    python3 evaluation/fts/scripts/measure_cost.py \
      --bundle "$BUNDLE" --corpus "$CORPUS" --out "$RESULTS/round$round" \
      --targets "$TARGETS" --core "$core" --variant "$variant" --reps "$reps" \
      > "$RESULTS/round$round/$variant.log" 2>&1 &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do wait "$pid" || exit 1; done
done
python3 evaluation/fts/scripts/summarize_cost.py \
  --rounds "$RESULTS/round1" "$RESULTS/round2" "$RESULTS/round3"
```

| Variant | Measurement | Repetitions per round | Outer timeout per input |
| --- | --- | --- | --- |
| `plain` | Plain QEMU | 3 | 60 s |
| `shm` | One QDMSan run with filling and checkpoints | 3 | 60 s |
| `qd` | Full QDMSan check, including confirmation | 3 | 180 s |
| `qmsan` | Accurate QMSan | 3 | 120 s |
| `memcheck` | Memcheck | 1 | 300 s |

`shm` creates the signature and selector shared memory used by QDMSan; it
executes once without comparing runs. Full checking uses a 5 s internal
per-run timeout. Inputs are regular files sorted by filename. `--inputs N`
limits each target to its first N files for a short trial.

Each round writes per-run logs and `cost_<variant>.json`. The summary first
computes each detector's median time divided by the plain-QEMU median within
that round. It then takes the median ratio across the three rounds, followed
by the geometric mean across targets. This matches Table 3's aggregation rule.
Inspect return codes as well as elapsed time: internal QDMSan timeouts and
outer timeouts are distinct.

[RESULTS.md](../RESULTS.md#timing-medians) contains the recorded per-round medians
and a command to recompute the paper table without executing the targets.
