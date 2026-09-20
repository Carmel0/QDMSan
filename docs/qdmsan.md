# QDMSan usage

Follow the [build and quick start](../README.md) first. Use the tools and
`libqdmsan.so` from the same `build/bin/` directory.

## Configuration

| Setting | Default | Purpose |
|---|---|---|
| `AFL_QDMSAN_MODE` | Unset | Set `fast` to enable QDMSan in AFL++; `full` also records checkpoint details |
| `AFL_QDMSAN_CHECK` / replay `-c` | `raw` | `raw` compares consumed values; `result` compares coarser comparison and libc results |
| `AFL_QDMSAN_DEPLOY` | `inline` | Reuse fuzz and calibration executions |
| `AFL_QDMSAN_STACK_MAX` | `4096` | Fill stack frames smaller than this bound, in bytes |
| `AFL_QDMSAN_HEAP_PLANES` | `0` | Set `1` to check heap accesses for OOB and UAF |
| `AFL_QDMSAN_FULL_SIZE` | `1048576` | Diagnostic map entries; increase if full-mode output reports collisions |

Do not combine `AFL_DMSAN_MODE` with `AFL_QDMSAN_MODE`. Leave
`AFL_QDMSAN_COMPAT_STUBS` unset: it changes selected libc behavior for synthetic
tests. Paper reproduction settings are described in
[repro/README.md](../repro/README.md).

## Diagnose a finding

Replay a saved input with `-m full` to list checkpoints whose values differ:

```sh
build/bin/qdmsan-diff -m full \
  -q "$PWD/build/bin/afl-qemu-trace" \
  -l "$PWD/build/bin/libqdmsan.so" \
  -i /path/to/finding -- /path/to/target @@
```

A `bug` result means a fill-dependent signature difference reproduced when the
first fill was repeated. Inspect the reported sites to identify the cause.
The decision still comes from compact signatures; full mode supplies location
details. In fast mode, `-C N` requests extra diagnostic triplets. `-C 0` retains
the normal mismatch-triggered confirmation run.

`-S` selects QD-State, the evaluation baseline that compares bucketed coverage
counts instead of consumed values. Its output reports `oracle=state`.

An explicit `-l` must agree with any `libqdmsan.so` already in `AFL_PRELOAD`.
For piped inputs, replay starts after standard input reaches EOF.

## Optional heap checks

The allocator fills redzones and quarantined freed blocks. A value read from
these regions can reach a UUM checkpoint even with heap checks disabled.
`AFL_QDMSAN_HEAP_PLANES=1` also hashes the affected bytes at memory accesses,
before a store overwrites them, and reports separate out-of-bounds (OOB) and
use-after-free (UAF) results. This adds a lookup per access and does not detect
double frees or provide complete heap addressability checking.

## Detection limits

- Static targets, non-x86-64 targets, and persistent mode are unsupported.
  Custom allocators can bypass heap filling.
- Instruction checkpoints cover the main executable. Libraries are checked at
  selected call boundaries, with bounded buffer prefixes.
- Stack fills cover bounded `SUB RSP` allocations and call scratch space. Other
  frame construction, reused slots, and larger frames can escape detection.
- Equal results across fills, unchecked uses, and signature collisions can hide
  bugs. A raw conditional-move checkpoint can also report an uninitialized value
  that is subsequently only stored.
- Time and random inputs are normalized, but other environmental differences
  and thread scheduling can still affect signatures. Repeating one run does not
  eliminate all non-determinism. Fatal exits are reported as crashes and may
  occur before all thread signatures are collected.
