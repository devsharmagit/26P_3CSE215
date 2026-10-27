# Scoring check: attacker alert-seconds the per-second scoring ignores (Friday)

Reproduce: `python -m experiments.scoring_check`. "Ignored" = seconds with a detection on 172.16.0.1 inside an
attack window (+5 s slack) in which the attacker sent nothing to the victim: neither hit nor false alarm in score().
"Strict precision" counts them as false alarms (segment of that attack).

F1 uses the segment recall (unchanged) with each precision. Segment = DEV for PortScan, TEST for DDoS.

| Configuration | Attack | attacker alert-seconds | hits | ignored | precision (as reported) | strict precision | F1 (as reported) | strict F1 |
|---|---|---|---|---|---|---|---|---|
| only rejected_probes | PortScan | 1,316 | 503 | 813 | 100.0 | 38.2 | 91.7 | 52.7 |
| only rejected_probes | DDoS | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 |
| count / fixed | PortScan | 174 | 141 | 33 | 99.3 | 80.6 | 38.3 | 36.7 |
| count / fixed | DDoS | 903 | 855 | 48 | 98.7 | 93.5 | 87.2 | 85.1 |
| behaviour / fixed | PortScan | 1,317 | 503 | 814 | 100.0 | 38.2 | 91.7 | 52.6 |
| behaviour / fixed | DDoS | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 |
| all / fixed | PortScan | 1,317 | 503 | 814 | 99.8 | 38.2 | 91.6 | 52.6 |
| all / fixed | DDoS | 903 | 855 | 48 | 98.7 | 93.5 | 87.2 | 85.1 |
| count / adaptive | PortScan | 174 | 141 | 33 | 99.3 | 80.6 | 38.3 | 36.7 |
| count / adaptive | DDoS | 901 | 854 | 47 | 98.7 | 93.6 | 87.1 | 85.1 |
| behaviour / adaptive | PortScan | 968 | 393 | 575 | 100.0 | 40.6 | 79.6 | 50.3 |
| behaviour / adaptive | DDoS | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 |
| all / adaptive | PortScan | 968 | 393 | 575 | 99.7 | 40.6 | 79.6 | 50.3 |
| all / adaptive | DDoS | 901 | 854 | 47 | 98.7 | 93.6 | 87.1 | 85.1 |
