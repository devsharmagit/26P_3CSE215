# T05: time to first true detection, per attack

Reproduce: `python -m experiments.grid wednesday && python -m experiments.derived_tables`
Consistency check: overall P/R/F1 of every row equal `results/<day>/results.json` exactly.

Two reference points: (a) the window start in days.py (Friday: CIC schedule minute; Wednesday: exact first attack
packet), (b) the first second in which the attacker sent traffic to the target in that window. "–" = never detected.

| Day | Attack | Configuration | TTD from window start (s) | TTD from first attack second (s) | recall |
|---|---|---|---|---|---|
| friday | PortScan | count / fixed | 3405.2 | 3373.2 | 23.7 |
| friday | DDoS | count / fixed | 43.5 | 12.5 | 78.1 |
| friday | PortScan | behaviour / fixed | 51.9 | 19.9 | 84.7 |
| friday | DDoS | behaviour / fixed | – | – | 0.0 |
| friday | PortScan | all / fixed | 51.9 | 19.9 | 84.7 |
| friday | DDoS | all / fixed | 43.5 | 12.5 | 78.1 |
| friday | PortScan | all / adaptive | 51.9 | 19.9 | 66.2 |
| friday | DDoS | all / adaptive | 43.5 | 12.5 | 78.0 |
| wednesday | DoS slowloris | count / fixed | 23.0 | 23.0 | 0.4 |
| wednesday | DoS Slowhttptest | count / fixed | 0.8 | 0.8 | 13.5 |
| wednesday | DoS Hulk | count / fixed | 0.1 | 0.1 | 50.2 |
| wednesday | DoS GoldenEye | count / fixed | 6.2 | 6.2 | 20.1 |
| wednesday | DoS slowloris | behaviour / fixed | – | – | 0.0 |
| wednesday | DoS Slowhttptest | behaviour / fixed | 4.8 | 4.8 | 33.6 |
| wednesday | DoS Hulk | behaviour / fixed | 1083.9 | 1083.9 | 0.2 |
| wednesday | DoS GoldenEye | behaviour / fixed | – | – | 0.0 |
| wednesday | DoS slowloris | all / fixed | 23.0 | 23.0 | 0.4 |
| wednesday | DoS Slowhttptest | all / fixed | 0.8 | 0.8 | 41.3 |
| wednesday | DoS Hulk | all / fixed | 0.1 | 0.1 | 50.4 |
| wednesday | DoS GoldenEye | all / fixed | 6.2 | 6.2 | 20.1 |
| wednesday | DoS slowloris | all / adaptive | 23.0 | 23.0 | 0.4 |
| wednesday | DoS Slowhttptest | all / adaptive | 0.8 | 0.8 | 34.9 |
| wednesday | DoS Hulk | all / adaptive | 0.1 | 0.1 | 50.2 |
| wednesday | DoS GoldenEye | all / adaptive | 6.2 | 6.2 | 20.1 |
