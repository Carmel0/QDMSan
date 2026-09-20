# QDMSan

QDMSan detects uses of uninitialized memory in Linux x86-64 binaries without
source code. It runs programs in QEMU with different memory fills and compares
values consumed at dangerous uses. It integrates with AFL++ and requires no
compiler instrumentation or shadow memory.

## Build

QDMSan supports dynamically linked x86-64 Linux targets using glibc. The build
has been tested on Ubuntu 22.04. QEMU and its dependencies are included.

```sh
sudo apt-get install build-essential clang git python3 meson ninja-build pkg-config \
  libglib2.0-dev libpixman-1-dev zlib1g-dev

git clone https://github.com/Carmel0/QDMSan.git
cd QDMSan
JOBS=4 ./build.sh
./test.sh
```

The executables and preload library are placed in `build/bin/`; build logs are
in `build-logs/`. Use these components together directly from the build directory.
See [tests](test_qdmsan/README.md) for individual test commands.

## Fuzz a binary

Create a `seeds/` directory containing at least one input, then run:

```sh
export AFL_PATH="$PWD/build/bin"
export AFL_PRELOAD="$PWD/build/bin/libqdmsan.so"
export AFL_QDMSAN_MODE=fast
export AFL_QDMSAN_CHECK=raw
"$AFL_PATH/afl-fuzz" -Q -i seeds -o findings -m none -- /path/to/target @@
```

`@@` is replaced with the input filename. Omit it for a target that reads from
standard input. QDMSan saves differential findings in
`findings/default/dmsan_findings/` and crashes in `findings/default/crashes/`.

## Check one input

```sh
build/bin/qdmsan-diff \
  -q "$PWD/build/bin/afl-qemu-trace" \
  -l "$PWD/build/bin/libqdmsan.so" \
  -i /path/to/input -- /path/to/target @@
```

The default policy compares consumed values (`-c raw`). Matching signatures
require two runs; a mismatch triggers a third run to check reproducibility.
Add `-m full` for checkpoint details. Run `build/bin/qdmsan-diff -h` for all options.

| Exit code | Result |
|---:|---|
| 0 | Clean |
| 1 | Bug |
| 2 | Non-deterministic |
| 3 | Crash |
| 4 | Timeout |
| 5 | Tool error |

See [usage](docs/qdmsan.md) for configuration, diagnostic output, and detection
limits.

## Paper and experiments

[AE.md](AE.md) provides the experiment instructions; [recorded results](evaluation/RESULTS.md)
summarize the paper's measurements.
[repro/README.md](repro/README.md) describes the paper's frozen tools and source
version; the current build includes fixes made after those measurements.
Only fixed real-world bug inputs are included. Inputs for unresolved cases and
the original campaign corpora are withheld.

## Licenses

AFL++ uses the [Apache 2.0 license](LICENSE). QEMU uses the
[GPL](qemu_mode/qemuafl/COPYING) and per-file licenses. QDMSan changes follow the
license of their host component. See [third-party notices](THIRD_PARTY_NOTICES.md)
for source revisions and dependencies.

Author: Jiami Lin.
