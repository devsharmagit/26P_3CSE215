# Bootstrap confidence intervals (revision 3, pre-registered)

Pre-registration: `docs/preregistration/confidence_intervals.md` (commit 3d3d237, before any computation).
Reproduce: `python -m experiments.ci_per_second && python -m experiments.bootstrap_ci`.

Moving-block bootstrap over seconds within each segment; B = 2000; seed 20261026 (`numpy.random.default_rng`); blocks drawn once per (segment, block length) and shared by all configurations (paired). 95% percentile intervals. Primary block length 60 s; 30 s and 300 s as sensitivity. F1 in %, point = full-sample value (equal to the published one). "Supported" = the 60 s interval excludes zero.

Scope: per-second sampling variability within these captures; not variability across attacks, attackers or datasets.

"paper (printed values)" = difference of the one-decimal values printed in the results files, as quoted in the paper; the bootstrap point uses unrounded F1 and can differ from it by 0.1.

## Fri DEV (24,011 s)

### F1 levels, 95% CI (block 60 s)

| Configuration | default | strict |
|---|---|---|
| count / fixed (= count @1s) | 38.3 [15.9, 57.4] | 36.7 [15.7, 53.4] |
| count / adaptive | 38.3 [15.9, 57.4] | 36.7 [15.7, 53.4] |
| behaviour / fixed (= behaviour @60s) | 91.7 [86.1, 95.4] | 52.6 [43.7, 61.0] |
| behaviour / adaptive | 79.6 [64.3, 89.9] | 50.3 [38.5, 60.4] |
| all / fixed | 91.6 [86.0, 95.4] | 52.6 [43.7, 61.0] |
| all / adaptive | 79.6 [64.2, 89.8] | 50.3 [38.5, 60.3] |
| all / adaptive, no freeze | 74.7 [56.6, 87.1] | 48.5 [36.1, 59.7] |
| behaviour @1s (s) | 65.6 [45.2, 80.9] | 46.3 [33.6, 56.7] |
| count @60s (p) | 53.2 [28.8, 72.7] | 36.5 [20.4, 49.9] |
| count @60s (u) | 52.7 [30.1, 71.4] | 36.0 [21.1, 48.7] |

### Paired differences (A − B)

| group | difference | scoring | paper (printed values) | point [95% CI], 60 s | supported | 30 s | 300 s |
|---|---|---|---|---|---|---|---|
| (a) | measure, unmatched: behaviour/fixed − count/fixed | default | 53.4 | 53.4 [35.0, 75.4] | yes | [38.4, 70.0] | [26.0, 85.4] |
| (a) | measure, unmatched: behaviour/fixed − count/fixed | strict | 15.9 | 16.0 [-0.8, 36.5] | **no** | [1.9, 31.7] | [-7.5, 47.4] |
| (a) | measure, matched 1 s: behaviour @1s (s) − count @1s | default | 27.3 | 27.3 [16.4, 41.3] | yes | [19.0, 37.7] | [12.2, 52.9] |
| (a) | measure, matched 1 s: behaviour @1s (s) − count @1s | strict | 9.6 | 9.6 [0.6, 20.6] | yes | [2.0, 18.3] | [-3.3, 30.0] |
| (a) | measure, matched 60 s: behaviour @60s − count @60s (p) | default | 38.5 | 38.6 [20.0, 62.4] | yes | [24.4, 55.7] | [12.5, 74.8] |
| (a) | measure, matched 60 s: behaviour @60s − count @60s (p) | strict | 16.1 | 16.1 [4.1, 32.2] | yes | [5.9, 28.4] | [1.7, 40.8] |
| (a) | measure, matched 60 s: behaviour @60s − count @60s (u) | default | 39.0 | 39.0 [21.0, 60.1] | yes | [25.2, 55.9] | [13.9, 72.8] |
| (a) | measure, matched 60 s: behaviour @60s − count @60s (u) | strict | 16.6 | 16.6 [5.6, 30.7] | yes | [7.0, 27.7] | [3.6, 38.4] |
| (b) | policy: count/fixed − count/adaptive | default | 0.0 | 0.0 [0.0, 0.0] | **no** | [0.0, 0.0] | [0.0, 0.0] |
| (b) | policy: count/fixed − count/adaptive | strict | 0.0 | 0.0 [0.0, 0.0] | **no** | [0.0, 0.0] | [0.0, 0.0] |
| (b) | policy: behaviour/fixed − behaviour/adaptive | default | 12.1 | 12.1 [3.3, 25.6] | yes | [4.9, 22.6] | [0.0, 35.8] |
| (b) | policy: behaviour/fixed − behaviour/adaptive | strict | 2.3 | 2.3 [-2.7, 9.5] | **no** | [-2.0, 8.6] | [-1.8, 12.2] |
| (b) | policy: all/fixed − all/adaptive | default | 12.0 | 12.1 [3.3, 25.6] | yes | [4.9, 22.6] | [0.0, 35.8] |
| (b) | policy: all/fixed − all/adaptive | strict | 2.3 | 2.3 [-2.7, 9.5] | **no** | [-2.0, 8.6] | [-1.8, 12.2] |
| (c) | freeze: all/adaptive − all/adaptive no freeze | default | 4.9 | 4.8 [0.0, 13.8] | **no** | [0.0, 11.5] | [0.0, 16.8] |
| (c) | freeze: all/adaptive − all/adaptive no freeze | strict | 1.8 | 1.8 [-0.8, 6.2] | **no** | [-0.7, 5.5] | [-0.3, 7.1] |
| (d) | |measure| − max |policy| (title claim) | default | – | 41.3 [23.4, 62.0] | yes | [27.7, 56.3] | [15.3, 74.0] |
| (d) | |measure| − max |policy| (title claim) | strict | – | 13.6 [-0.2, 33.1] | **no** | [0.9, 27.8] | [-1.9, 43.2] |

## Fri TEST (4,962 s)

### F1 levels, 95% CI (block 60 s)

| Configuration | default | strict |
|---|---|---|
| count / fixed (= count @1s) | 87.2 [84.7, 89.4] | 85.1 [81.8, 87.9] |
| count / adaptive | 87.1 [84.6, 89.4] | 85.1 [81.7, 87.9] |
| behaviour / fixed (= behaviour @60s) | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| behaviour / adaptive | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| all / fixed | 87.2 [84.7, 89.4] | 85.1 [81.8, 87.9] |
| all / adaptive | 87.1 [84.6, 89.4] | 85.1 [81.7, 87.9] |
| all / adaptive, no freeze | 11.6 [3.6, 22.7] | 11.6 [3.6, 22.7] |
| behaviour @1s (s) | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| count @60s (p) | 96.5 [92.9, 98.4] | 91.9 [86.9, 95.5] |
| count @60s (u) | 96.5 [92.9, 98.4] | 91.9 [86.9, 95.5] |

### Paired differences (A − B)

| group | difference | scoring | paper (printed values) | point [95% CI], 60 s | supported | 30 s | 300 s |
|---|---|---|---|---|---|---|---|
| (a) | measure, unmatched: behaviour/fixed − count/fixed | default | -87.2 | -87.2 [-89.4, -84.7] | yes | [-89.4, -84.8] | [-89.6, -84.4] |
| (a) | measure, unmatched: behaviour/fixed − count/fixed | strict | -85.1 | -85.1 [-87.9, -81.8] | yes | [-87.9, -82.3] | [-88.0, -81.7] |
| (b) | policy: count/fixed − count/adaptive | default | 0.1 | 0.1 [0.0, 0.2] | **no** | [0.0, 0.2] | [0.0, 0.2] |
| (b) | policy: count/fixed − count/adaptive | strict | 0.0 | 0.0 [-0.1, 0.1] | **no** | [-0.1, 0.1] | [-0.0, 0.1] |
| (b) | policy: behaviour/fixed − behaviour/adaptive | default | 0.0 | 0.0 [0.0, 0.0] | **no** | [0.0, 0.0] | [0.0, 0.0] |
| (b) | policy: behaviour/fixed − behaviour/adaptive | strict | 0.0 | 0.0 [0.0, 0.0] | **no** | [0.0, 0.0] | [0.0, 0.0] |
| (b) | policy: all/fixed − all/adaptive | default | 0.1 | 0.1 [0.0, 0.2] | **no** | [0.0, 0.2] | [0.0, 0.2] |
| (b) | policy: all/fixed − all/adaptive | strict | 0.0 | 0.0 [-0.1, 0.1] | **no** | [-0.1, 0.1] | [-0.0, 0.1] |
| (c) | freeze: all/adaptive − all/adaptive no freeze | default | 75.5 | 75.6 [63.4, 84.5] | yes | [65.8, 83.4] | [60.3, 85.6] |
| (c) | freeze: all/adaptive − all/adaptive no freeze | strict | 73.5 | 73.5 [61.8, 82.7] | yes | [63.8, 81.5] | [58.8, 83.2] |
| (d) | |measure| − max |policy| (title claim) | default | – | 87.1 [84.6, 89.4] | yes | [84.7, 89.4] | [84.3, 89.6] |
| (d) | |measure| − max |policy| (title claim) | strict | – | 85.1 [81.7, 87.9] | yes | [82.2, 87.8] | [81.6, 87.9] |

## Wed (30,453 s)

### F1 levels, 95% CI (block 60 s)

| Configuration | default | strict |
|---|---|---|
| count / fixed (= count @1s) | 25.8 [19.5, 32.5] | 25.6 [19.4, 32.3] |
| count / adaptive | 25.8 [19.5, 32.5] | 25.6 [19.4, 32.3] |
| behaviour / fixed (= behaviour @60s) | 16.7 [6.2, 28.7] | 16.7 [6.2, 28.7] |
| behaviour / adaptive | 13.3 [3.6, 24.8] | 13.3 [3.6, 24.8] |
| all / fixed | 36.5 [26.7, 47.0] | 36.3 [26.6, 46.8] |
| all / adaptive | 34.1 [24.9, 44.3] | 33.9 [24.8, 44.0] |
| all / adaptive, no freeze | 29.8 [21.2, 39.8] | 29.7 [21.1, 39.5] |
| behaviour @1s (s) | 16.7 [6.2, 28.7] | 16.7 [6.2, 28.7] |
| count @60s (p) | 40.0 [28.6, 52.1] | 34.9 [25.6, 44.7] |
| count @60s (u) | 39.4 [28.0, 51.6] | 34.5 [25.3, 44.3] |

### Paired differences (A − B)

| group | difference | scoring | paper (printed values) | point [95% CI], 60 s | supported | 30 s | 300 s |
|---|---|---|---|---|---|---|---|
| (a) | measure, unmatched: behaviour/fixed − count/fixed | default | -9.1 | -9.1 [-21.3, 3.5] | **no** | [-18.5, 0.4] | [-28.1, 8.2] |
| (a) | measure, unmatched: behaviour/fixed − count/fixed | strict | -8.9 | -9.0 [-21.0, 3.5] | **no** | [-18.3, 0.5] | [-27.8, 8.2] |
| (b) | policy: count/fixed − count/adaptive | default | 0.0 | 0.0 [0.0, 0.0] | **no** | [0.0, 0.0] | [0.0, 0.0] |
| (b) | policy: count/fixed − count/adaptive | strict | 0.0 | 0.0 [0.0, 0.0] | **no** | [0.0, 0.0] | [0.0, 0.0] |
| (b) | policy: behaviour/fixed − behaviour/adaptive | default | 3.4 | 3.3 [-0.0, 9.6] | **no** | [0.1, 7.7] | [-0.0, 10.2] |
| (b) | policy: behaviour/fixed − behaviour/adaptive | strict | 3.4 | 3.3 [-0.0, 9.5] | **no** | [0.1, 7.7] | [-0.0, 10.2] |
| (b) | policy: all/fixed − all/adaptive | default | 2.4 | 2.4 [-0.0, 6.7] | **no** | [0.0, 5.4] | [-0.0, 7.2] |
| (b) | policy: all/fixed − all/adaptive | strict | 2.4 | 2.3 [-0.0, 6.7] | **no** | [0.0, 5.3] | [-0.0, 7.1] |
| (c) | freeze: all/adaptive − all/adaptive no freeze | default | 4.3 | 4.3 [0.9, 9.0] | yes | [1.4, 7.8] | [0.3, 10.0] |
| (c) | freeze: all/adaptive − all/adaptive no freeze | strict | 4.2 | 4.3 [0.9, 9.0] | yes | [1.4, 7.8] | [0.3, 10.0] |
| (d) | |measure| − max |policy| (title claim) | default | – | 5.8 [-5.7, 20.0] | **no** | [-4.6, 17.0] | [-6.8, 27.0] |
| (d) | |measure| − max |policy| (title claim) | strict | – | 5.6 [-5.7, 19.7] | **no** | [-4.6, 16.8] | [-6.8, 26.6] |

## STOP-FLAG check (pre-registration §4)

Intervals for (a), (b) or (c) that include zero at 60 s: **21**.

- Fri DEV: measure, unmatched: behaviour/fixed − count/fixed (strict)
- Fri DEV: policy: count/fixed − count/adaptive (default)
- Fri DEV: policy: count/fixed − count/adaptive (strict)
- Fri DEV: policy: behaviour/fixed − behaviour/adaptive (strict)
- Fri DEV: policy: all/fixed − all/adaptive (strict)
- Fri DEV: freeze: all/adaptive − all/adaptive no freeze (default)
- Fri DEV: freeze: all/adaptive − all/adaptive no freeze (strict)
- Fri TEST: policy: count/fixed − count/adaptive (default)
- Fri TEST: policy: count/fixed − count/adaptive (strict)
- Fri TEST: policy: behaviour/fixed − behaviour/adaptive (default)
- Fri TEST: policy: behaviour/fixed − behaviour/adaptive (strict)
- Fri TEST: policy: all/fixed − all/adaptive (default)
- Fri TEST: policy: all/fixed − all/adaptive (strict)
- Wed: measure, unmatched: behaviour/fixed − count/fixed (default)
- Wed: measure, unmatched: behaviour/fixed − count/fixed (strict)
- Wed: policy: count/fixed − count/adaptive (default)
- Wed: policy: count/fixed − count/adaptive (strict)
- Wed: policy: behaviour/fixed − behaviour/adaptive (default)
- Wed: policy: behaviour/fixed − behaviour/adaptive (strict)
- Wed: policy: all/fixed − all/adaptive (default)
- Wed: policy: all/fixed − all/adaptive (strict)

## Deviations from the pre-registration

None in method. Presentation only: the column "paper (printed values)" was added after the first run, because the
bootstrap point of a difference (unrounded) can differ by 0.1 from the difference the paper quotes (e.g. 16.0 vs 15.9).
Rerunning with the same seed reproduced every interval exactly.
