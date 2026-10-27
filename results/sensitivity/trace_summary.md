# Per-second trace summary (Friday 15:54-16:20 ADT, count rules, adaptive, floor 1)

Source: `trace_per_second.csv`, written by `experiments/paper_figures.py` (re-runs the configurations unchanged).

| configuration | windows traced | seconds with a detection on 172.16.0.1 (any count rule) |
|---|---|---|
| m=3, freeze (default) | 1441 | 901 |
| m=3, no freeze | 1441 | 68 |
| m=4, freeze | 1441 | 1 |
