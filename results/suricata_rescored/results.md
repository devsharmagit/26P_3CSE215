# T03b: Suricata re-scored with the current scoring (Friday)

Suricata 8.0.7 (`out_et/suricata.log`: "52768 rules successfully loaded"; `out_custom/suricata.log`: 4 rules),
HOME_NET 192.168.10.0/24. Scored with `experiments.Truth` + `experiments.score` (victim-only positives, 5 s slack).
Reproduce: `python -m baselines.suricata.eval_suricata_v2` (needs <data>/suricata/out_et/ and out_custom/ from baselines/suricata/run_suricata.sh).

| View | alerts (scored) | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS | TTD PortScan (s) | TTD DDoS (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ET Open (52,768 rules), every alert | 1,405,383 | 0.6 | 9.6 | 1.0 | 1538.4 | 10.7 | 25.3 | 15.1 | 1669.0 | 9.6 | 25.3 | 57.9 | 42.3 |
| ET Open, ET signatures only | 1,749 | 17.3 | 8.6 | 11.5 | 36.6 | 44.4 | 1.8 | 3.5 | 18.1 | 8.6 | 1.8 | 57.9 | 49.8 |
| ET Open, ET SCAN / ET DOS signatures only | 207 | 100.0 | 8.6 | 15.8 | 0.0 | 100.0 | 1.8 | 3.6 | 0.0 | 8.6 | 1.8 | 57.9 | 49.8 |
| custom threshold rules (4) | 9,481 | 97.7 | 28.3 | 43.9 | 0.6 | 99.8 | 82.4 | 90.2 | 1.5 | 28.3 | 82.4 | 3405.5 | 45.7 |

Alerts without a source IP (not attributable, skipped): ET Open (52,768 rules), every alert: 7,279 of 1,412,662; ET Open, ET signatures only: 7,279 of 1,412,662; ET Open, ET SCAN / ET DOS signatures only: 7,279 of 1,412,662; custom threshold rules (4): 0 of 9,481
