# T02: Wednesday (held-out) 2x2 + no-freeze, per attack

Exact Friday thresholds (rules.yaml unchanged); nothing was chosen on Wednesday. Reproduce: `python -m experiments.grid wednesday && python -m experiments.derived_tables`
Consistency check: overall P/R/F1 of every row equal `results/<day>/results.json` exactly.

Per-attack precision counts the false-alarm seconds inside that attack's own span (first to last attack second + 5 s).
Overall = whole capture (08:42-17:10 ADT), day-wide false-alarm seconds.

| Configuration | overall P | overall R | overall F1 | FP/h | DoS slowloris P / R / F1 | DoS Slowhttptest P / R / F1 | DoS Hulk P / R / F1 | DoS GoldenEye P / R / F1 |
|---|---|---|---|---|---|---|---|---|
| count / fixed | 99.3 | 14.8 | 25.8 | 0.4 | 100.0 / 0.4 / 0.8 | 100.0 / 13.5 / 23.7 | 100.0 / 50.2 / 66.8 | 100.0 / 20.1 / 33.5 |
| count / adaptive | 99.3 | 14.8 | 25.8 | 0.4 | 100.0 / 0.4 / 0.8 | 100.0 / 13.5 / 23.7 | 100.0 / 50.2 / 66.8 | 100.0 / 20.1 / 33.5 |
| behaviour / fixed | 97.5 | 9.1 | 16.7 | 0.8 | 0.0 / 0.0 / 0.0 | 100.0 / 33.6 / 50.3 | 100.0 / 0.2 / 0.4 | 0.0 / 0.0 / 0.0 |
| behaviour / adaptive | 98.2 | 7.1 | 13.3 | 0.5 | 0.0 / 0.0 / 0.0 | 100.0 / 26.4 / 41.8 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| all / fixed | 98.6 | 22.4 | 36.5 | 1.2 | 100.0 / 0.4 / 0.8 | 100.0 / 41.3 / 58.5 | 100.0 / 50.4 / 67.0 | 100.0 / 20.1 / 33.5 |
| all / adaptive | 98.9 | 20.6 | 34.1 | 0.8 | 100.0 / 0.4 / 0.8 | 100.0 / 34.9 / 51.8 | 100.0 / 50.2 / 66.8 | 100.0 / 20.1 / 33.5 |
| all / adaptive, no freeze | 98.9 | 17.6 | 29.8 | 0.7 | 100.0 / 0.2 / 0.3 | 100.0 / 28.2 / 44.0 | 100.0 / 50.2 / 66.8 | 100.0 / 11.8 / 21.2 |

## Answers

- Measure vs threshold: count 25.8 -> all 36.5 F1 (fixed); fixed vs adaptive: count 25.8 vs 25.8, behaviour 16.7 vs 13.3, all 36.5 vs 34.1.
- Freeze: all / adaptive 34.1 vs without freeze 29.8 F1.

