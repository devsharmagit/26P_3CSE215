# R2: default configurations reproduce Table III

Reproduce: `python -m experiments.window_matching reproduce`. Each row re-runs a Table III configuration
with the engine after the window change and compares the full score() output (per-segment TP, FP seconds, P, R,
F1, FP/h and per-window recall and TTD, as unrounded floats) with `results/<day>/results.json`.

| Day | Configuration | DEV/all F1 | TEST F1 | identical to results.json |
|---|---|---|---|---|
| friday | count / fixed | 38.3 | 87.2 | yes |
| friday | count / adaptive | 38.3 | 87.1 | yes |
| friday | behaviour / fixed | 91.7 | 0.0 | yes |
| friday | behaviour / adaptive | 79.6 | 0.0 | yes |
| friday | all / fixed | 91.6 | 87.2 | yes |
| friday | all / adaptive | 79.6 | 87.1 | yes |
| friday | all / adaptive, no freeze | 74.7 | 11.6 | yes |
| wednesday | count / fixed | 25.8 | – | yes |
| wednesday | count / adaptive | 25.8 | – | yes |
| wednesday | behaviour / fixed | 16.7 | – | yes |
| wednesday | behaviour / adaptive | 13.3 | – | yes |
| wednesday | all / fixed | 36.5 | – | yes |
| wednesday | all / adaptive | 34.1 | – | yes |
| wednesday | all / adaptive, no freeze | 29.8 | – | yes |

All identical: **yes**. Wall time 100 s (8 processes).
