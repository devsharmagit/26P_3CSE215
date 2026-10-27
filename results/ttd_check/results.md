# TTD check: first true alert vs first attacker alert (Friday baselines)

Reproduce: `python -m experiments.ttd_check`. "stored" = `score()` ttd as printed in
`results/suricata_rescored/results.md`; "first true alert" = the definition of Table V and `derived_tables.py`.

| Detector | attack | stored TTD (s) | first true alert (s) |
|---|---|---|---|
| Suricata: ET Open (52,768 rules), every alert | PortScan | 57.9 | 57.9 |
| Suricata: ET Open (52,768 rules), every alert | DDoS | 42.3 | 42.3 |
| Suricata: ET Open, ET signatures only | PortScan | 57.9 | 57.9 |
| Suricata: ET Open, ET signatures only | DDoS | 49.8 | 49.8 |
| Suricata: ET Open, ET SCAN / ET DOS signatures only | PortScan | 57.9 | 57.9 |
| Suricata: ET Open, ET SCAN / ET DOS signatures only | DDoS | 49.8 | 49.8 |
| Suricata: custom threshold rules (4) | PortScan | 3405.5 | 3405.5 |
| Suricata: custom threshold rules (4) | DDoS | 45.7 | 45.7 |
