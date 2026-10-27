# T04: best fixed vs best adaptive, and threshold sensitivity (Friday)

Design: docs/preregistration/sensitivity_sweep.md (fixed before the run).
Fixed: strictness scale s on every rule of the family. Adaptive: floor scale f x multiplier level
(counts and rejected_probes m = (1.5, 2, 3, 4, 6); half_open and port_entropy m = (1.05, 1.1, 1.25, 1.5, 2)); alpha 0.2, freeze 60 s.
DEV = 08:59-15:40 (PortScan), TEST = 15:40-17:03 (DDoS). Reproduce: `python -m experiments.sensitivity`.

## 1. Best by DEV F1, reported on TEST (held-out protocol)

| Family | Policy | Setting chosen on DEV | DEV F1 | TEST F1 | DEV FP/h | TEST FP/h |
|---|---|---|---|---|---|---|
| count | fixed | s=1.5 | 38.4 | 82.5 | 0.0 | 2.9 |
| count | adaptive | floor=1, m-level=1 | 38.3 | 87.2 | 0.1 | 8.0 |
| behaviour | fixed | s=0.25 | 96.0 | 0.0 | 0.0 | 20.3 |
| behaviour | adaptive | floor=0.25, m-level=1 | 96.0 | 0.0 | 0.0 | 20.3 |
| all | fixed | s=0.75 | 92.7 | 89.5 | 1.8 | 10.9 |
| all | adaptive | floor=0.5, m-level=1 | 85.2 | 90.2 | 18.7 | 23.2 |

## 2. Oracle: best F1 of each policy on each segment (any setting in the grid)

| Family | Segment | best fixed F1 (setting) | best adaptive F1 (setting) | adaptive - fixed |
|---|---|---|---|---|
| count | DEV | 38.4 (s=1.5) | 38.3 (floor=1, m-level=1) | -0.1 |
| count | TEST | 90.2 (s=0.5) | 90.2 (floor=0.5, m-level=1) | +0.0 |
| behaviour | DEV | 96.0 (s=0.25) | 96.0 (floor=0.25, m-level=1) | +0.0 |
| behaviour | TEST | 0.0 (s=0.25) | 0.0 (floor=0.25, m-level=1) | +0.0 |
| all | DEV | 92.7 (s=0.75) | 85.2 (floor=0.5, m-level=1) | -7.5 |
| all | TEST | 90.2 (s=0.5) | 90.2 (floor=0.5, m-level=1) | +0.0 |

**Does any adaptive setting beat the best fixed setting?** No: on every family and segment the best adaptive F1 is at most the best fixed F1.

## 3. Every setting

| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |
|---|---|---|---|---|---|---|---|---|---|---|
| count / fixed s=0.25 | 14.5 | 26.6 | 18.8 | 139.9 | 85.8 | 90.2 | 88.0 | 118.3 | 26.6 | 90.2 |
| count / fixed s=0.5 | 53.0 | 23.7 | 32.8 | 18.7 | 96.7 | 84.6 | 90.2 | 23.2 | 23.7 | 84.6 |
| count / fixed s=0.75 | 92.2 | 23.7 | 37.8 | 1.8 | 98.4 | 82.1 | 89.5 | 10.9 | 23.7 | 82.1 |
| count / fixed s=1 | 99.3 | 23.7 | 38.3 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 23.7 | 78.1 |
| count / fixed s=1.5 | 100.0 | 23.7 | 38.4 | 0.0 | 99.5 | 70.4 | 82.5 | 2.9 | 23.7 | 70.4 |
| count / fixed s=2 | 100.0 | 23.7 | 38.4 | 0.0 | 100.0 | 61.2 | 75.9 | 0.0 | 23.7 | 61.2 |
| count / fixed s=3 | 100.0 | 23.6 | 38.1 | 0.0 | 100.0 | 42.1 | 59.3 | 0.0 | 23.6 | 42.1 |
| count / adaptive floor=0.25 m-level=1 | 14.5 | 26.6 | 18.8 | 139.9 | 85.8 | 90.2 | 88.0 | 118.3 | 26.6 | 90.2 |
| count / adaptive floor=0.25 m-level=2 | 14.5 | 26.6 | 18.8 | 139.9 | 85.9 | 90.2 | 88.0 | 117.6 | 26.6 | 90.2 |
| count / adaptive floor=0.25 m-level=3 | 15.3 | 26.6 | 19.4 | 131.3 | 86.9 | 90.2 | 88.5 | 108.1 | 26.6 | 90.2 |
| count / adaptive floor=0.25 m-level=4 | 17.2 | 26.6 | 20.9 | 114.1 | 88.0 | 90.2 | 89.1 | 98.0 | 26.6 | 90.2 |
| count / adaptive floor=0.25 m-level=5 | 21.0 | 23.7 | 22.3 | 79.3 | 90.0 | 90.2 | 90.1 | 79.8 | 23.7 | 90.2 |
| count / adaptive floor=0.5 m-level=1 | 53.0 | 23.7 | 32.8 | 18.7 | 96.7 | 84.6 | 90.2 | 23.2 | 23.7 | 84.6 |
| count / adaptive floor=0.5 m-level=2 | 53.0 | 23.7 | 32.8 | 18.7 | 96.7 | 84.6 | 90.2 | 23.2 | 23.7 | 84.6 |
| count / adaptive floor=0.5 m-level=3 | 55.7 | 23.7 | 33.3 | 16.8 | 96.4 | 79.0 | 86.8 | 23.2 | 23.7 | 79.0 |
| count / adaptive floor=0.5 m-level=4 | 59.7 | 23.7 | 34.0 | 14.2 | 3.2 | 0.1 | 0.2 | 21.8 | 23.7 | 0.1 |
| count / adaptive floor=0.5 m-level=5 | 72.7 | 23.7 | 35.8 | 7.9 | 0.0 | 0.0 | 0.0 | 16.7 | 23.7 | 0.0 |
| count / adaptive floor=1 m-level=1 | 99.3 | 23.7 | 38.3 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 23.7 | 78.1 |
| count / adaptive floor=1 m-level=2 | 99.3 | 23.7 | 38.3 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 23.7 | 78.1 |
| count / adaptive floor=1 m-level=3 | 99.3 | 23.7 | 38.3 | 0.1 | 98.7 | 78.0 | 87.1 | 8.0 | 23.7 | 78.0 |
| count / adaptive floor=1 m-level=4 | 99.3 | 23.7 | 38.3 | 0.1 | 8.3 | 0.1 | 0.2 | 8.0 | 23.7 | 0.1 |
| count / adaptive floor=1 m-level=5 | 99.3 | 23.7 | 38.3 | 0.1 | 0.0 | 0.0 | 0.0 | 7.3 | 23.7 | 0.0 |
| behaviour / fixed s=0.25 | 100.0 | 92.3 | 96.0 | 0.0 | 0.0 | 0.0 | 0.0 | 20.3 | 92.3 | 0.0 |
| behaviour / fixed s=0.5 | 100.0 | 90.1 | 94.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 90.1 | 0.0 |
| behaviour / fixed s=0.75 | 100.0 | 88.2 | 93.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 88.2 | 0.0 |
| behaviour / fixed s=1 | 100.0 | 84.7 | 91.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 84.7 | 0.0 |
| behaviour / fixed s=1.5 | 100.0 | 75.6 | 86.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 75.6 | 0.0 |
| behaviour / fixed s=2 | 100.0 | 64.0 | 78.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 64.0 | 0.0 |
| behaviour / fixed s=3 | 100.0 | 58.1 | 73.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 58.1 | 0.0 |
| behaviour / adaptive floor=0.25 m-level=1 | 100.0 | 92.3 | 96.0 | 0.0 | 0.0 | 0.0 | 0.0 | 20.3 | 92.3 | 0.0 |
| behaviour / adaptive floor=0.25 m-level=2 | 100.0 | 92.3 | 96.0 | 0.0 | 0.0 | 0.0 | 0.0 | 20.3 | 92.3 | 0.0 |
| behaviour / adaptive floor=0.25 m-level=3 | 100.0 | 92.3 | 96.0 | 0.0 | 0.0 | 0.0 | 0.0 | 20.3 | 92.3 | 0.0 |
| behaviour / adaptive floor=0.25 m-level=4 | 100.0 | 79.0 | 88.2 | 0.0 | 0.0 | 0.0 | 0.0 | 20.3 | 79.0 | 0.0 |
| behaviour / adaptive floor=0.25 m-level=5 | 100.0 | 63.8 | 77.9 | 0.0 | 0.0 | 0.0 | 0.0 | 20.3 | 63.8 | 0.0 |
| behaviour / adaptive floor=0.5 m-level=1 | 100.0 | 89.9 | 94.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 89.9 | 0.0 |
| behaviour / adaptive floor=0.5 m-level=2 | 100.0 | 69.4 | 81.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 69.4 | 0.0 |
| behaviour / adaptive floor=0.5 m-level=3 | 100.0 | 68.5 | 81.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 68.5 | 0.0 |
| behaviour / adaptive floor=0.5 m-level=4 | 100.0 | 67.3 | 80.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 67.3 | 0.0 |
| behaviour / adaptive floor=0.5 m-level=5 | 100.0 | 63.8 | 77.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 63.8 | 0.0 |
| behaviour / adaptive floor=1 m-level=1 | 100.0 | 66.2 | 79.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 66.2 | 0.0 |
| behaviour / adaptive floor=1 m-level=2 | 100.0 | 66.2 | 79.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 66.2 | 0.0 |
| behaviour / adaptive floor=1 m-level=3 | 100.0 | 66.2 | 79.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 66.2 | 0.0 |
| behaviour / adaptive floor=1 m-level=4 | 100.0 | 66.2 | 79.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 66.2 | 0.0 |
| behaviour / adaptive floor=1 m-level=5 | 100.0 | 63.8 | 77.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 63.8 | 0.0 |
| all / fixed s=0.25 | 37.0 | 92.3 | 52.8 | 139.9 | 83.8 | 90.2 | 86.9 | 138.6 | 92.3 | 90.2 |
| all / fixed s=0.5 | 81.1 | 90.1 | 85.3 | 18.7 | 96.7 | 84.6 | 90.2 | 23.2 | 90.1 | 84.6 |
| all / fixed s=0.75 | 97.8 | 88.2 | 92.7 | 1.8 | 98.4 | 82.1 | 89.5 | 10.9 | 88.2 | 82.1 |
| all / fixed s=1 | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all / fixed s=1.5 | 100.0 | 75.6 | 86.1 | 0.0 | 99.5 | 70.4 | 82.5 | 2.9 | 75.6 | 70.4 |
| all / fixed s=2 | 100.0 | 64.0 | 78.0 | 0.0 | 100.0 | 61.2 | 75.9 | 0.0 | 64.0 | 61.2 |
| all / fixed s=3 | 100.0 | 58.1 | 73.5 | 0.0 | 100.0 | 42.1 | 59.3 | 0.0 | 58.1 | 42.1 |
| all / adaptive floor=0.25 m-level=1 | 37.0 | 92.3 | 52.8 | 139.9 | 83.8 | 90.2 | 86.9 | 138.6 | 92.3 | 90.2 |
| all / adaptive floor=0.25 m-level=2 | 37.0 | 92.3 | 52.8 | 139.9 | 83.9 | 90.2 | 86.9 | 137.9 | 92.3 | 90.2 |
| all / adaptive floor=0.25 m-level=3 | 38.5 | 92.3 | 54.3 | 131.3 | 84.8 | 90.2 | 87.4 | 128.4 | 92.3 | 90.2 |
| all / adaptive floor=0.25 m-level=4 | 38.1 | 79.0 | 51.4 | 114.1 | 85.8 | 90.2 | 88.0 | 118.3 | 79.0 | 90.2 |
| all / adaptive floor=0.25 m-level=5 | 41.7 | 63.8 | 50.5 | 79.3 | 87.7 | 90.2 | 89.0 | 100.1 | 63.8 | 90.2 |
| all / adaptive floor=0.5 m-level=1 | 81.0 | 89.9 | 85.2 | 18.7 | 96.7 | 84.6 | 90.2 | 23.2 | 89.9 | 84.6 |
| all / adaptive floor=0.5 m-level=2 | 76.7 | 69.4 | 72.9 | 18.7 | 96.7 | 84.6 | 90.2 | 23.2 | 69.4 | 84.6 |
| all / adaptive floor=0.5 m-level=3 | 78.4 | 68.5 | 73.1 | 16.8 | 96.4 | 79.0 | 86.8 | 23.2 | 68.5 | 79.0 |
| all / adaptive floor=0.5 m-level=4 | 80.8 | 67.3 | 73.5 | 14.2 | 3.2 | 0.1 | 0.2 | 21.8 | 67.3 | 0.1 |
| all / adaptive floor=0.5 m-level=5 | 87.7 | 63.8 | 73.9 | 7.9 | 0.0 | 0.0 | 0.0 | 16.7 | 63.8 | 0.0 |
| all / adaptive floor=1 m-level=1 | 99.7 | 66.2 | 79.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 66.2 | 78.1 |
| all / adaptive floor=1 m-level=2 | 99.7 | 66.2 | 79.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 66.2 | 78.1 |
| all / adaptive floor=1 m-level=3 | 99.7 | 66.2 | 79.6 | 0.1 | 98.7 | 78.0 | 87.1 | 8.0 | 66.2 | 78.0 |
| all / adaptive floor=1 m-level=4 | 99.7 | 66.2 | 79.6 | 0.1 | 8.3 | 0.1 | 0.2 | 8.0 | 66.2 | 0.1 |
| all / adaptive floor=1 m-level=5 | 99.7 | 63.8 | 77.8 | 0.1 | 0.0 | 0.0 | 0.0 | 7.3 | 63.8 | 0.0 |

## 4. Thresholds used per setting

See results.json (`thresholds` per run).
