# Results: wednesday

Held-out day: never used to choose a threshold. Attacker 172.16.0.1 -> 192.168.10.50; windows verified in the capture.

Positives (attacker-active seconds): DoS slowloris 1303, DoS Slowhttptest 825, DoS Hulk 500, DoS GoldenEye 422

## 1. Rule family x threshold policy

Rows change WHAT is measured, the two rows of each family change only HOW the threshold is set.

| Configuration | ALL P | ALL R | ALL F1 | ALL FP/h | recall DoS slowloris | recall DoS Slowhttptest | recall DoS Hulk | recall DoS GoldenEye |
|---|---|---|---|---|---|---|---|---|
| count / fixed | 99.3 | 14.8 | 25.8 | 0.4 | 0.4 | 13.5 | 50.2 | 20.1 |
| count / adaptive | 99.3 | 14.8 | 25.8 | 0.4 | 0.4 | 13.5 | 50.2 | 20.1 |
| behaviour / fixed | 97.5 | 9.1 | 16.7 | 0.8 | 0.0 | 33.6 | 0.2 | 0.0 |
| behaviour / adaptive | 98.2 | 7.1 | 13.3 | 0.5 | 0.0 | 26.4 | 0.0 | 0.0 |
| all / fixed | 98.6 | 22.4 | 36.5 | 1.2 | 0.4 | 41.3 | 50.4 | 20.1 |
| all / adaptive | 98.9 | 20.6 | 34.1 | 0.8 | 0.4 | 34.9 | 50.2 | 20.1 |

### Compact view (F1 per segment)

| Rule family | fixed ALL | adaptive ALL |
|---|---|---|
| count | 25.8 | 25.8 |
| behaviour | 16.7 | 13.3 |
| all | 36.5 | 34.1 |

## 2. Safeguard: adaptive thresholds without the baseline freeze

| Configuration | ALL P | ALL R | ALL F1 | ALL FP/h | recall DoS slowloris | recall DoS Slowhttptest | recall DoS Hulk | recall DoS GoldenEye |
|---|---|---|---|---|---|---|---|---|
| all / adaptive | 98.9 | 20.6 | 34.1 | 0.8 | 0.4 | 34.9 | 50.2 | 20.1 |
| all / adaptive, no freeze | 98.9 | 17.6 | 29.8 | 0.7 | 0.2 | 28.2 | 50.2 | 11.8 |

## 3. Each rule alone (fixed thresholds)

| Configuration | ALL P | ALL R | ALL F1 | ALL FP/h | recall DoS slowloris | recall DoS Slowhttptest | recall DoS Hulk | recall DoS GoldenEye |
|---|---|---|---|---|---|---|---|---|
| only syn_flood | 99.1 | 10.6 | 19.2 | 0.4 | 0.0 | 11.6 | 42.0 | 4.3 |
| only icmp_flood | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| only port_sweep | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| only victim_packet_flood | 99.3 | 9.6 | 17.6 | 0.2 | 0.1 | 2.5 | 47.8 | 7.8 |
| only victim_conn_flood | 99.5 | 14.3 | 24.9 | 0.2 | 0.3 | 13.2 | 50.2 | 16.8 |
| only half_open | 97.5 | 9.1 | 16.7 | 0.8 | 0.0 | 33.6 | 0.2 | 0.0 |
| only port_entropy | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| only rejected_probes | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

## 4. All rules minus one (fixed thresholds)

| Configuration | ALL P | ALL R | ALL F1 | ALL FP/h | recall DoS slowloris | recall DoS Slowhttptest | recall DoS Hulk | recall DoS GoldenEye |
|---|---|---|---|---|---|---|---|---|
| all / fixed (none removed) | 98.6 | 22.4 | 36.5 | 1.2 | 0.4 | 41.3 | 50.4 | 20.1 |
| all minus syn_flood | 98.7 | 22.4 | 36.5 | 1.1 | 0.4 | 41.3 | 50.4 | 20.1 |
| all minus icmp_flood | 98.6 | 22.4 | 36.5 | 1.2 | 0.4 | 41.3 | 50.4 | 20.1 |
| all minus port_sweep | 98.6 | 22.4 | 36.5 | 1.2 | 0.4 | 41.3 | 50.4 | 20.1 |
| all minus victim_packet_flood | 98.5 | 21.8 | 35.7 | 1.2 | 0.3 | 41.1 | 50.4 | 16.8 |
| all minus victim_conn_flood | 98.4 | 20.1 | 33.4 | 1.2 | 0.1 | 40.7 | 48.6 | 7.8 |
| all minus half_open | 99.3 | 14.8 | 25.8 | 0.4 | 0.4 | 13.5 | 50.2 | 20.1 |
| all minus port_entropy | 98.6 | 22.4 | 36.5 | 1.2 | 0.4 | 41.3 | 50.4 | 20.1 |
| all minus rejected_probes | 98.6 | 22.4 | 36.5 | 1.2 | 0.4 | 41.3 | 50.4 | 20.1 |

## 5. Transparent score as an alert filter (all rules)

score = sum of the weights of the rules that fired for the host in that second (all weights are 1, so
score = number of rules that agree). Only detections with score >= k are kept.

| Configuration | ALL P | ALL R | ALL F1 | ALL FP/h | recall DoS slowloris | recall DoS Slowhttptest | recall DoS Hulk | recall DoS GoldenEye |
|---|---|---|---|---|---|---|---|---|
| all / fixed, score >= 1 | 98.6 | 22.4 | 36.5 | 1.2 | 0.4 | 41.3 | 50.4 | 20.1 |
| all / fixed, score >= 2 | 99.5 | 12.0 | 21.4 | 0.2 | 0.0 | 12.6 | 48.4 | 4.5 |
| all / fixed, score >= 3 | 99.3 | 9.1 | 16.8 | 0.2 | 0.0 | 6.5 | 41.4 | 4.3 |
| all / adaptive, score >= 1 | 98.9 | 20.6 | 34.1 | 0.8 | 0.4 | 34.9 | 50.2 | 20.1 |
| all / adaptive, score >= 2 | 99.5 | 11.9 | 21.3 | 0.2 | 0.0 | 12.4 | 48.4 | 4.5 |
| all / adaptive, score >= 3 | 99.3 | 9.0 | 16.5 | 0.2 | 0.0 | 6.1 | 41.4 | 4.3 |

## 5b. Sensitivity of the rejected-probes rule (rule alone, fixed)

Its default (> 10 rejected probes in 60 s) was chosen after looking at the Friday attacker, so this table
shows how much the result depends on that choice.

| Configuration | ALL P | ALL R | ALL F1 | ALL FP/h | recall DoS slowloris | recall DoS Slowhttptest | recall DoS Hulk | recall DoS GoldenEye |
|---|---|---|---|---|---|---|---|---|
| rejected_probes > 3 in 30 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 5 in 30 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 10 in 30 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 20 in 30 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 40 in 30 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 3 in 60 s | 0.0 | 0.0 | 0.0 | 0.2 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 5 in 60 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 10 in 60 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 20 in 60 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 40 in 60 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 3 in 120 s | 0.0 | 0.0 | 0.0 | 7.3 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 5 in 120 s | 0.0 | 0.0 | 0.0 | 1.1 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 10 in 120 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 20 in 120 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes > 40 in 120 s | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

## 6. Reference

Legacy AdaptiveRuleEngine settings (legacy_rules.yaml; reproduces adaptive_engine.py exactly).

| Configuration | ALL P | ALL R | ALL F1 | ALL FP/h | recall DoS slowloris | recall DoS Slowhttptest | recall DoS Hulk | recall DoS GoldenEye |
|---|---|---|---|---|---|---|---|---|
| legacy AdaptiveRuleEngine | 88.4 | 22.4 | 35.7 | 10.6 | 0.4 | 41.3 | 50.4 | 20.1 |

## False alarms (all / fixed)

Hosts with a false-alarm second: 3 (of which not attackers: 2); top: [('192.168.10.15', 7), ('172.16.0.1', 2), ('192.168.10.17', 1)]

Detections per rule in false-alarm seconds: {'half_open': 7, 'syn_flood': 3, 'victim_conn_flood': 2, 'victim_packet_flood': 2}
