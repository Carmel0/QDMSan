# QDMSan preload runtime

`libqdmsan.so` intercepts heap allocation and selected libc calls. It requests
memory fills from QEMU, records values consumed at library boundaries, and uses
QEMU's controlled time and random sources.

Build and run it with the matching QEMU and AFL++ binaries using the
[root instructions](../../README.md). The build writes the library to
`build/bin/libqdmsan.so`; fuzzing loads it through `AFL_PRELOAD`, and replay uses
the `-l` option.

The allocator maintains poisoned redzones and a quarantine. Set
`AFL_QDMSAN_HEAP_PLANES=1` to enable access checks and separate OOB/UAF reports.
Without it, loaded poisoned values can still be detected at UUM checkpoints.
See [configuration and limits](../../docs/qdmsan.md) for details.
