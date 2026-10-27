# Results: friday

DEV = 08:59-15:40 (PortScan), TEST = 15:40-17:03 (DDoS). Attacker 172.16.0.1 -> 192.168.10.50.

Positives (attacker-active seconds): PortScan 594, DDoS 1095

## 1. Rule family x threshold policy

Rows change WHAT is measured, the two rows of each family change only HOW the threshold is set.

| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |
|---|---|---|---|---|---|---|---|---|---|---|
| count / fixed | 99.3 | 23.7 | 38.3 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 23.7 | 78.1 |
| count / adaptive | 99.3 | 23.7 | 38.3 | 0.1 | 98.7 | 78.0 | 87.1 | 8.0 | 23.7 | 78.0 |
| behaviour / fixed | 100.0 | 84.7 | 91.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 84.7 | 0.0 |
| behaviour / adaptive | 100.0 | 66.2 | 79.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 66.2 | 0.0 |
| all / fixed | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all / adaptive | 99.7 | 66.2 | 79.6 | 0.1 | 98.7 | 78.0 | 87.1 | 8.0 | 66.2 | 78.0 |

### Compact view (F1 per segment)

| Rule family | fixed DEV | fixed TEST | adaptive DEV | adaptive TEST |
|---|---|---|---|---|
| count | 38.3 | 87.2 | 38.3 | 87.1 |
| behaviour | 91.7 | 0.0 | 79.6 | 0.0 |
| all | 91.6 | 87.2 | 79.6 | 87.1 |

## 2. Safeguard: adaptive thresholds without the baseline freeze

| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |
|---|---|---|---|---|---|---|---|---|---|---|
| all / adaptive | 99.7 | 66.2 | 79.6 | 0.1 | 98.7 | 78.0 | 87.1 | 8.0 | 66.2 | 78.0 |
| all / adaptive, no freeze | 99.7 | 59.8 | 74.7 | 0.1 | 86.1 | 6.2 | 11.6 | 8.0 | 59.8 | 6.2 |

## 3. Each rule alone (fixed thresholds)

| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |
|---|---|---|---|---|---|---|---|---|---|---|
| only syn_flood | 100.0 | 23.6 | 38.1 | 0.0 | 100.0 | 39.6 | 56.8 | 0.0 | 23.6 | 39.6 |
| only icmp_flood | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| only port_sweep | 100.0 | 23.7 | 38.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 23.7 | 0.0 |
| only victim_packet_flood | 0.0 | 0.0 | 0.0 | 0.0 | 98.5 | 65.9 | 79.0 | 8.0 | 0.0 | 65.9 |
| only victim_conn_flood | 99.3 | 23.7 | 38.3 | 0.1 | 100.0 | 78.0 | 87.6 | 0.0 | 23.7 | 78.0 |
| only half_open | 100.0 | 45.3 | 62.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 45.3 | 0.0 |
| only port_entropy | 100.0 | 29.8 | 45.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 29.8 | 0.0 |
| only rejected_probes | 100.0 | 84.7 | 91.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 84.7 | 0.0 |

## 4. All rules minus one (fixed thresholds)

| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |
|---|---|---|---|---|---|---|---|---|---|---|
| all / fixed (none removed) | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all minus syn_flood | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all minus icmp_flood | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all minus port_sweep | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all minus victim_packet_flood | 99.8 | 84.7 | 91.6 | 0.1 | 100.0 | 78.0 | 87.6 | 0.0 | 84.7 | 78.0 |
| all minus victim_conn_flood | 100.0 | 84.7 | 91.7 | 0.0 | 98.5 | 65.9 | 79.0 | 8.0 | 84.7 | 65.9 |
| all minus half_open | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all minus port_entropy | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all minus rejected_probes | 99.6 | 45.3 | 62.3 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 45.3 | 78.1 |

## 5. Transparent score as an alert filter (all rules)

score = sum of the weights of the rules that fired for the host in that second (all weights are 1, so
score = number of rules that agree). Only detections with score >= k are kept.

| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |
|---|---|---|---|---|---|---|---|---|---|---|
| all / fixed, score >= 1 | 99.8 | 84.7 | 91.6 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 84.7 | 78.1 |
| all / fixed, score >= 2 | 100.0 | 45.3 | 62.3 | 0.0 | 100.0 | 65.8 | 79.4 | 0.0 | 45.3 | 65.8 |
| all / fixed, score >= 3 | 100.0 | 29.8 | 45.9 | 0.0 | 100.0 | 39.6 | 56.8 | 0.0 | 29.8 | 39.6 |
| all / adaptive, score >= 1 | 99.7 | 66.2 | 79.6 | 0.1 | 98.7 | 78.0 | 87.1 | 8.0 | 66.2 | 78.0 |
| all / adaptive, score >= 2 | 100.0 | 37.9 | 54.9 | 0.0 | 100.0 | 56.0 | 71.8 | 0.0 | 37.9 | 56.0 |
| all / adaptive, score >= 3 | 100.0 | 29.8 | 45.9 | 0.0 | 100.0 | 0.2 | 0.4 | 0.0 | 29.8 | 0.2 |

## 5b. Sensitivity of the rejected-probes rule (rule alone, fixed)

Its default (> 10 rejected probes in 60 s) was chosen after looking at the Friday attacker, so this table
shows how much the result depends on that choice.

| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |
|---|---|---|---|---|---|---|---|---|---|---|
| rejected_probes > 3 in 30 s | 100.0 | 90.6 | 95.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 90.6 | 0.0 |
| rejected_probes > 5 in 30 s | 100.0 | 86.7 | 92.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 86.7 | 0.0 |
| rejected_probes > 10 in 30 s | 100.0 | 62.5 | 76.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 62.5 | 0.0 |
| rejected_probes > 20 in 30 s | 100.0 | 48.8 | 65.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 48.8 | 0.0 |
| rejected_probes > 40 in 30 s | 100.0 | 37.9 | 54.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 37.9 | 0.0 |
| rejected_probes > 3 in 60 s | 100.0 | 91.6 | 95.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 91.6 | 0.0 |
| rejected_probes > 5 in 60 s | 100.0 | 90.1 | 94.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 90.1 | 0.0 |
| rejected_probes > 10 in 60 s | 100.0 | 84.7 | 91.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 84.7 | 0.0 |
| rejected_probes > 20 in 60 s | 100.0 | 59.1 | 74.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 59.1 | 0.0 |
| rejected_probes > 40 in 60 s | 100.0 | 47.0 | 63.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 47.0 | 0.0 |
| rejected_probes > 3 in 120 s | 100.0 | 92.6 | 96.2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 92.6 | 0.0 |
| rejected_probes > 5 in 120 s | 100.0 | 91.6 | 95.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 91.6 | 0.0 |
| rejected_probes > 10 in 120 s | 100.0 | 89.9 | 94.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 89.9 | 0.0 |
| rejected_probes > 20 in 120 s | 100.0 | 78.8 | 88.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 78.8 | 0.0 |
| rejected_probes > 40 in 120 s | 100.0 | 60.1 | 75.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 60.1 | 0.0 |

## 6. Reference

Legacy AdaptiveRuleEngine settings (legacy_rules.yaml; reproduces adaptive_engine.py exactly).

| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |
|---|---|---|---|---|---|---|---|---|---|---|
| legacy AdaptiveRuleEngine | 82.5 | 45.3 | 58.5 | 8.5 | 97.7 | 78.0 | 86.7 | 14.5 | 45.3 | 78.0 |

## False alarms (all / fixed)

Hosts with a false-alarm second: 2 (of which not attackers: 2); top: [('192.168.10.12', 11), ('192.168.10.8', 1)]

Detections per rule in false-alarm seconds: {'victim_conn_flood': 1, 'victim_packet_flood': 11}
