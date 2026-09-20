# Artifact evaluation

QDMSan detects uses of uninitialized memory in x86-64 Linux binaries. The
[README](README.md) covers installation and use. This guide covers the paper's
experiments; [recorded results](evaluation/RESULTS.md) are presented as tables.

| Experiment | Materials | Reproduction |
| --- | --- | --- |
| Labeled tests (Table 2) | 13 synthetic pairs, pinned Juliet selection, build and replay scripts | Build and run all 931 pairs |
| Fuzzing and cost (Table 3) | Target settings, cost drivers, recorded results | Run cost measurements on supplied targets and inputs; the historical corpus is withheld |
| Real bugs (Table 4) | CycloneDDS and glog inputs, pinned vulnerable and fixed sources | Build and replay these two cases |

Only real-world inputs for bugs fixed upstream are distributed. Other bug inputs and
the mixed historical fuzzing corpus are withheld. The paper results used the
[paper version](repro/README.md); v0.1.0 includes subsequent fixes. Use tools from
one version consistently and record that version with new results.

## Requirements

Run commands from the repository root on x86-64 Linux. Install QDMSan as described
in the README, plus Python 3.10 or newer, GCC/G++, and Clang. Baseline runs also
need Valgrind or QMSan. The original compilers were GCC/G++ 11.4.0 for Juliet and
Clang 18.1.8 for the synthetic controls. The scripts compile ordinary binaries
without sanitizer instrumentation.

## 1. Synthetic controls

The 13 pairs cover benign propagation and dangerous consumption. Compiling each
at `-O0` and `-O2` produces 26 clean and 26 buggy programs.

```sh
python3 evaluation/scripts/run_capability.py build controls \
  --cc clang-18 --out /tmp/qd-controls
python3 evaluation/scripts/run_capability.py run controls --out /tmp/qd-controls \
  --tool QDMSan --qd-diff build/bin/qdmsan-diff \
  --qemu build/bin/afl-qemu-trace --runtime build/bin/libqdmsan.so
python3 evaluation/scripts/summarize.py /tmp/qd-controls/controls-QDMSan.tsv
```

Use `--cc clang` if that is the installed compiler name. Each replay writes a TSV
and individual logs under the output directory. Expected QDMSan results are 26
UUM reports and 26 clean classifications. For a short check, pass `--limit 4` to
both build and run.

## 2. Juliet CWE-457

The fetcher verifies the SHA256 of the public
[NIST Juliet C/C++ 1.3 archive](https://samate.nist.gov/SARD/downloads/test-suites/2017-11-02-juliet-c-cplusplus-v1-3.zip)
and extracts the 905 selected pairs. Flow variant 12 is excluded because its
random branch is suppressed by QEMU's deterministic random inputs.

```sh
python3 evaluation/scripts/fetch_juliet.py \
  --archive /tmp/juliet-c-cpp-v1.3.zip --out /tmp/qd-juliet-source
python3 evaluation/scripts/run_capability.py build juliet \
  --juliet-source /tmp/qd-juliet-source --out /tmp/qd-juliet
python3 evaluation/scripts/run_capability.py run juliet --out /tmp/qd-juliet \
  --tool QDMSan --qd-diff build/bin/qdmsan-diff \
  --qemu build/bin/afl-qemu-trace --runtime build/bin/libqdmsan.so
python3 evaluation/scripts/summarize.py /tmp/qd-juliet/juliet-QDMSan.tsv
```

The first command requires a new output directory; it reuses a downloaded
archive if present. Build and run accept `--limit N`. The selection and link
order are recorded in [juliet.tsv](evaluation/manifests/juliet.tsv).
The paper counts target crashes as findings, separately from UUM confirmations;
it does not count timeouts. See [Table 2](evaluation/RESULTS.md#table-2-labeled-tests)
for the breakdown.

### Baselines

The same runner accepts `--tool QD-State`, `--tool Memcheck`, or `--tool QMSan`.
QD-State takes the same QDMSan path arguments; for the paper version, use its
separate `qdmsan-state-diff` helper. Memcheck uses `valgrind` on `PATH` or
`--memcheck /path/to/valgrind`. QMSan requires `--qmsan /path/to/qmsan`, pointing
to the accurate detector launcher.

| Baseline | Version used |
| --- | --- |
| Memcheck | Valgrind 3.18.1 |
| [QMSan](https://github.com/heinzeen/qmsan) | `8d4233f712dbfcd74c0570d12a287193dbf6846c` |
| [AFL-QMSan](https://github.com/Heinzeen/AFL-QMSan) | `d252acf05b6a7414235897a809ae007a3ba24b54` |

Build QMSan's accurate detector with `python3 build.py --msan --taint`.
For Clang 18, its `afl/afl-qemu-cpu-inl.h` initializer
`static struct afl_tsl exit_cmd_tsl = {{-1, 0, 0, 0}, NULL};` needs `0` in place
of `NULL` in the integer field. Follow each baseline's own dependency instructions.
Use the same compiled test binaries for every detector.

To combine results, pass all generated TSV files to `summarize.py`.
The runner clears inherited detector settings so the selected tool paths and
command-line options determine each run.

## 3. Fuzzing and cost

The paper used six Fuzzer Test Suite targets and one 12-hour campaign per
target/tool. The historical input corpus is not included. Target versions,
counts, detection results, timing medians and counting rules are in
[RESULTS.md](evaluation/RESULTS.md#table-3-real-program-campaigns-and-cost).

The [cost guide](evaluation/fts/README.md) describes how to supply a target bundle
and corpus to the standalone measurement scripts. Measurements
on a new corpus are new results, not a rerun of the withheld paper corpus.

## 4. Fixed real-world bugs

Follow [fixed-cases/README.md](evaluation/fixed-cases/README.md) to build and replay
CycloneDDS and glog. The scripts pin vulnerable and fixed revisions and check
the distributed input hashes. The glog fix is in its maintained successor,
ng-log; the archived google/glog project has no release containing that fix.
