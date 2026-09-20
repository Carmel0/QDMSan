# Fixed real-world bugs

This directory contains the CycloneDDS and glog inputs from the paper whose
bugs have been fixed upstream. Other real-bug inputs remain withheld.

| Case | Vulnerable revision | Fixed revision |
| --- | --- | --- |
| CycloneDDS | `c7b1e48a5bdbcedf16e7500594f335905ed76fbb` | `61b007559d821604025917d1721bc740b6cb832d` ([PR 2424](https://github.com/eclipse-cyclonedds/cyclonedds/pull/2424)) |
| glog | `53d58e4531c7c90f71ddab503d915e027432447a` | ng-log `ece82e12f85a5ec60b6153382ce81af292d5c78e` ([PR 34](https://github.com/ng-log/ng-log/pull/34)) |

The archived [glog project](https://github.com/google/glog#readme) recommends
ng-log as a maintained, API-compatible successor. The fix is included in
[ng-log v0.8.3](https://github.com/ng-log/ng-log/releases/tag/v0.8.3), not in a
google/glog release.

## Build

Install Git, CMake, Clang/Clang++ and OpenSSL development headers (`libssl-dev`
on Ubuntu). Run from the repository root:

```sh
python3 evaluation/fixed-cases/build.py glog vulnerable --work /tmp/glog-vulnerable
python3 evaluation/fixed-cases/build.py glog fixed --work /tmp/ng-log-fixed
python3 evaluation/fixed-cases/build.py cyclonedds vulnerable --work /tmp/dds-vulnerable
python3 evaluation/fixed-cases/build.py cyclonedds fixed --work /tmp/dds-fixed
```

Each command requires a new work directory. The build uses the upstream fuzz
harness and a file-input driver, without sanitizer instrumentation. `build.json`
records the executable path, source revision, compiler and options. Use `--cc`
and `--cxx` to select a compiler; the original experiment used Clang 18.1.8.

## Replay

For example, select the glog executable built above:

```sh
TARGET=$(python3 -c 'import json; print("/tmp/glog-vulnerable/" + json.load(open("/tmp/glog-vulnerable/build.json"))["target"])')
python3 evaluation/fixed-cases/replay.py glog --target "$TARGET" \
  --qd-diff build/bin/qdmsan-diff --qemu build/bin/afl-qemu-trace \
  --runtime build/bin/libqdmsan.so
python3 evaluation/fixed-cases/replay.py glog --target "$TARGET" --tool memcheck
```

Use `cyclonedds` and the corresponding build directory for the other case.
QDMSan returns 1 for a confirmed difference; Memcheck returns 99 for an error.
The glog runner sets `AFL_QDMSAN_STACK_MAX=8192` to cover its 4104-byte stack
frame. Its size exceeds the default exclusive bound of 4096; keep this setting
when using the QD-State baseline as well.

## Expected results

Both paper-tool replays confirmed UUM in three runs. Rebuilt targets tested
with the release tools produced the following results:

| Target | Version | QDMSan exit | Memcheck exit |
| --- | --- | --- | --- |
| CycloneDDS | Vulnerable | 1 | 99 |
| CycloneDDS | Fixed | 0 | 0 |
| glog | Vulnerable | 1 | 99 |
| ng-log | Fixed | 0 | 0 |

These checks concern the supplied inputs. Compiler changes can affect the
behavior of uninitialized data, so keep build metadata with each new result.
