# Recorded paper results

These tables report the paper experiments with the [paper tools](../repro/README.md).
The release contains subsequent fixes; new runs should be reported separately.

## Table 2: labeled tests

Each suite pairs buggy programs with clean counterparts. Entries in the first
four result columns count detections on buggy programs; the two clean columns
count correctly accepted clean programs. Headings give each group's total.

| Detector | Juliet values (800) | Juliet pointers (105) | Branch/address (20) | Output (6) | Clean Juliet (905) | Clean controls (26) |
| --- | --- | --- | --- | --- | --- | --- |
| QMSan | 800 | 105 | 20 | 2 | 905 | 25 |
| Memcheck | 800 | 105 | 20 | 6 | 905 | 26 |
| QD-State | 0 | 84 | 2 | 0 | 905 | 26 |
| QDMSan | 800 | 105 | 20 | 6 | 905 | 26 |

The 905 Juliet pairs exclude 43 flow-12 pairs whose random branch is suppressed by
QEMU's deterministic random inputs. QDMSan's bad-case count includes 821 UUM
reports and 84 target crashes (81 caused by filling); timeouts are not findings.
The 13 supplementary pairs are compiled at both `-O0` and `-O2`. Their results
do not exclude false reports on other code, such as some conditional-move idioms.

## Table 3: real-program campaigns and cost

Each target/tool campaign ran for 12 hours, with one trial. TP counts distinct
UUM sites confirmed with Memcheck, grouped by target and the innermost function
of the first reported error. Campaign findings include saved target crashes as
well as sanitizer reports. FP counts distinct causes of false findings.
Intentional re2 SparseSet/SparseArray uses are excluded at the individual report
level.

| Target | QDMSan TP | QDMSan FP | AFL-QMSan TP | AFL-QMSan FP |
| --- | --- | --- | --- | --- |
| libxml2-v2.9.2 | 3 | 0 | 4 | 0 |
| pcre2-10.00 | 1 | 0 | 2 | 0 |
| re2-2014-12-09 | 0 | 0 | 0 | 0 |
| openssl-1.0.1f | 2 | 0 | 1 | 0 |
| json-2017-02-12 | 0 | 0 | 0 | 1 |
| guetzli-2017-3-30 | 1 | 0 | 1 | 0 |
| Overall | 7 | 0 | 8 | 1 |

The two campaigns share six confirmed UUM sites. These sites do not necessarily
represent independent bugs.

QMSan saved 74 spurious inputs on json, all caused by one fault in its
opportunistic emulator and counted as one FP. Native debugging confirmed that
the pcre2 input previously counted as FP triggers a real out-of-bounds scan.
It maps to an existing QMSan site under the same function grouping, so it
contributes neither an FP nor an additional TP.

### Standalone detection cost

All five configurations ran concurrently on separate physical cores of one machine,
using the same 69,314 inputs. The experiment has three complete rounds. Within
each round, plain QEMU, QDMSan single run, QDMSan full check and accurate QMSan
have three repetitions each; Memcheck has one.

For each target and round, divide the detector's median elapsed time by the
plain-QEMU median from that same round. The table reports the median of these
three ratios. Overall is the geometric mean across the six targets, calculated
before rounding. Repetitions from different rounds are not pooled.

| Target | Memcheck | QMSan accurate | QDMSan single run | QDMSan full check |
| --- | --- | --- | --- | --- |
| libxml2-v2.9.2 | 16.35x | 2.73x | 1.32x | 2.00x |
| pcre2-10.00 | 17.04x | 3.83x | 1.62x | 2.39x |
| re2-2014-12-09 | 13.61x | 8.23x | 2.66x | 5.13x |
| openssl-1.0.1f | 12.06x | 3.65x | 1.96x | 3.66x |
| json-2017-02-12 | 14.97x | 2.80x | 1.33x | 1.95x |
| guetzli-2017-3-30 | 4.90x | 6.26x | 2.06x | 3.94x |
| Overall | 12.24x | 4.20x | 1.77x | 2.97x |

### Timing medians

The per-round medians are sufficient to recompute Table 3:

```sh
python3 evaluation/fts/scripts/summarize_cost.py --recorded evaluation/RESULTS.md
```

<details>
<summary>Per-round timing medians (seconds)</summary>

| Round | Target | Inputs | Plain QEMU | QDMSan single run | QDMSan full check | QMSan accurate | Memcheck |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | libxml2-v2.9.2 | 13836 | 743.568 | 981.791 | 1489.249 | 2033.377 | 12206.078 |
| 1 | pcre2-10.00 | 39758 | 1807.864 | 2938.111 | 4333.669 | 6916.816 | 30949.446 |
| 1 | re2-2014-12-09 | 8762 | 532.621 | 1419.676 | 2734.865 | 4384.894 | 7246.695 |
| 1 | openssl-1.0.1f | 730 | 64.665 | 126.944 | 236.655 | 236.553 | 780.019 |
| 1 | json-2017-02-12 | 2979 | 157.029 | 208.381 | 306.064 | 441.307 | 2351.235 |
| 1 | guetzli-2017-3-30 | 3249 | 725.361 | 1493.015 | 2856.959 | 4538.187 | 3556.510 |
| 2 | libxml2-v2.9.2 | 13836 | 749.341 | 986.527 | 1497.339 | 2041.143 | 12248.878 |
| 2 | pcre2-10.00 | 39758 | 1822.481 | 2955.306 | 4347.080 | 6976.958 | 31048.379 |
| 2 | re2-2014-12-09 | 8762 | 534.124 | 1422.220 | 2740.126 | 4395.983 | 7270.778 |
| 2 | openssl-1.0.1f | 730 | 64.702 | 128.330 | 238.512 | 236.420 | 781.408 |
| 2 | json-2017-02-12 | 2979 | 157.523 | 210.113 | 306.838 | 440.452 | 2359.575 |
| 2 | guetzli-2017-3-30 | 3249 | 725.440 | 1501.479 | 2862.464 | 4545.091 | 3557.850 |
| 3 | libxml2-v2.9.2 | 13836 | 750.399 | 987.782 | 1494.745 | 2070.577 | 12262.194 |
| 3 | pcre2-10.00 | 39758 | 1841.317 | 2978.367 | 4375.525 | 6980.072 | 31007.292 |
| 3 | re2-2014-12-09 | 8762 | 540.748 | 1427.865 | 2746.249 | 4384.702 | 7258.624 |
| 3 | openssl-1.0.1f | 730 | 66.063 | 128.641 | 237.320 | 235.234 | 780.873 |
| 3 | json-2017-02-12 | 2979 | 159.796 | 209.586 | 306.203 | 441.339 | 2356.836 |
| 3 | guetzli-2017-3-30 | 3249 | 730.558 | 1499.174 | 2858.563 | 4540.569 | 3561.137 |

</details>

Elapsed costs include unsuccessful runs. Each pcre2 single-run repetition has
126 signal-11 exits and one outer timeout; full QDMSan checking has three pcre2
and 17 re2 internal timeouts per repetition. An outer-timeout counter of zero
does not imply all checks completed. The corpus was filtered by QEMU execution,
not native execution: 21 pcre2 inputs crash natively although plain QEMU exits 0.

The historical corpus includes undisclosed findings and is not distributed.
The [cost guide](fts/README.md) describes measurements with caller-provided
targets and inputs.

## Fixed real-world cases

Build and replay instructions, revisions and expected results are in
[fixed-cases/README.md](fixed-cases/README.md). Only CycloneDDS and glog inputs
are included; the other six paper cases remain withheld pending fixes.
