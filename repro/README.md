# Paper version

The paper used the September 14 measurement binaries. Download
`qdmsan-paper-tools-20260914-linux-x86_64.tar.gz` from the
[v0.1.0 release](https://github.com/Carmel0/QDMSan/releases/tag/v0.1.0)
and verify its `SHA256SUMS` before use. The archive includes a separate
`qdmsan-state-diff` helper for the QD-State baseline.

The regular v0.1.0 tools include subsequent fixes to replay, allocation,
thread-exit accounting and calibration coverage handling. Use the paper tools
for comparisons with the recorded results.

## Build the paper source

Apply the restoration patch in a separate checkout:

```sh
git clone https://github.com/Carmel0/QDMSan.git QDMSan-paper
cd QDMSan-paper
git checkout v0.1.0
git apply repro/release-to-paper.patch
sha256sum -c repro/SHA256SUMS
JOBS=4 ./build.sh
```

The checksums cover the files changed by the restoration patch. Its source
revisions were AFL++ `d4e7d50443463995a650816c1d76a0b2ea623d2a` and
QEMU-AFL `0389a38a3a22e7ebc9e056caac427899d0912756`; their code is supplied
by the patch, so these local research commits do not need to be fetched.
The release build scripts and vendored dependencies remain in place.

To build the paper's QD-State helper, apply
`evaluation/manifests/qd-state-paper.patch` after the checksum check, then
run `make -C utils/qdmsan-diff`.

## Run the paper tools

Use the QEMU, preload library and replay executable from the same archive:

```sh
paper-tools/qdmsan-diff -q "$PWD/paper-tools/afl-qemu-trace" \
  -l "$PWD/paper-tools/libqdmsan.so" -i input -- /path/to/target @@
```

For fuzzing, set `AFL_PATH` and `AFL_PRELOAD` to that directory and its
`libqdmsan.so`. Follow the commands in [README.md](../README.md).

`AFL_QDMSAN_PAPER_COMPAT=1` restores only the old calibration and thread
accounting in the release tools. It is not a substitute for the paper version.
Rebuilt timing depends on the compiler and machine. Available experiments and
inputs are described in [AE.md](../AE.md).
