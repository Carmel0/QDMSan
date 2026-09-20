# Third-party source and licenses

The repository preserves upstream copyright and license notices. There is no
single replacement license for every vendored component.

| Component | Source identity | License location |
|---|---|---|
| AFL++ | `b449e4c544eaac1a0a9b7d1f2f15d5921907585e` | `LICENSE` (Apache 2.0) and per-file notices |
| QEMU-AFL | `60ebd5624c60589e276cf287516b925a9ee35b87` | `qemu_mode/qemuafl/COPYING`, `COPYING.LIB`, and per-file notices |
| Capstone | Pinned in `UPSTREAM_BASELINE.json` | `qemu_mode/qemuafl/capstone/LICENSE.TXT` and component notices |
| libslirp | Pinned in `UPSTREAM_BASELINE.json` | `qemu_mode/qemuafl/slirp/COPYRIGHT` |
| keycodemapdb | Pinned in `UPSTREAM_BASELINE.json` | `qemu_mode/qemuafl/ui/keycodemapdb/LICENSE.BSD`, `LICENSE.GPL2` |
| Berkeley SoftFloat / TestFloat | Pinned in `UPSTREAM_BASELINE.json` | `qemu_mode/qemuafl/tests/fp/berkeley-*/COPYING.txt` |

QDMSan modifications to existing components follow their respective licenses.
New AFL++ host tools, the preload library, build scripts, and synthetic release
tests are distributed under the root Apache 2.0 license unless a file states
otherwise. New QEMU runtime and translation code follows QEMU's GPL licensing.
This also applies to the corresponding-source materials in `repro/`.

Additional test sources and external benchmark instructions in `evaluation/`
retain the attribution and license information recorded there. Public benchmark
sources are fetched separately rather than being relicensed by this repository.
