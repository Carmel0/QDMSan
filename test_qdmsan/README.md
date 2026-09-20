# QDMSan tests

From the repository root, build the tools and run the regression suite:

```sh
./build.sh
./test.sh
```

The suite checks differential decisions, default and optional heap checks,
inline fuzzing, replay input handling, calibration, thread and fork accounting,
and allocator and libc behavior. It uses synthetic programs included here and
requires no external test sources. Host and runtime reports are written under
`build/tests/`.

## Individual tests

Bind the build before running individual scripts:

```sh
export QDMSAN_DIFF="$PWD/build/bin/qdmsan-diff"
export AFL_QDMSAN_QEMU="$PWD/build/bin/afl-qemu-trace"
export AFL_QDMSAN_LIB="$PWD/build/bin/libqdmsan.so"
export QDMSAN_AFL_FUZZ="$PWD/build/bin/afl-fuzz"
export AFL_PATH="$PWD/build/bin"
export AFL_PRELOAD="$PWD/build/bin/libqdmsan.so"

./test_qdmsan/run_qdmsan_suite.sh local
./test_qdmsan/run_qdmsan_suite.sh nondet
./test_qdmsan/run_three_plane_unit.sh
./test_qdmsan/run_three_plane_smoke.sh
./test_qdmsan/run_inline_three_plane_smoke.sh
./test_qdmsan/run_inline_full_smoke.sh
./test_qdmsan/run_allocator_stress.sh
```

`local` runs cases listed in `manifests/qdmsan_local.tsv`; `nondet` selects its
environmental normalization cases. `raw` and `result` select the corresponding
check policy; `all` is an alias for `local`. Their results and Markdown summaries are
written to `test_qdmsan/results/`. Override the output and build directories with
`QDMSAN_TEST_OUT_DIR` and `QDMSAN_TEST_BUILD_DIR`.

The three-plane tests check that clean inputs use two runs, a difference in any
plane triggers one confirmation run, and the candidate and confirmed masks
match. Heap cases include reads and writes to redzones or quarantined blocks.
The inline tests check that AFL++ saves the resulting findings.

The runner maps replay exit codes to `clean` (0), `report` (1), `nondet` (2),
`crash` (3), `timeout` (4), or `runtime_error`.
