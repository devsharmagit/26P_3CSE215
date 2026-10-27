# Window-matching experiment (revision 2, pre-registered)

Pre-registration: `docs/preregistration/window_matching.md` (commit 6525bee, before any code change or run).
Reproduce: `python -m experiments.window_matching`. All runs use fixed thresholds.

Default = the paper's per-second scoring (`experiments.score`). Strict = attacker alert-seconds inside an attack
window in which the attacker sent nothing to the victim count as false alarms (`scoring_check.py`, here applied to
every segment). F1 uses the same recall under both rules. TTD = first true alert (an alert on the attacker in a
second with attacker -> victim traffic), s after the window start, as in Table IV (`derived_tables.py`).

## 1. Friday

| Configuration | DEV P | DEV R | DEV F1 | DEV strict P | DEV strict F1 | scan TTD | TEST P | TEST R | TEST F1 | TEST strict P | TEST strict F1 | DDoS TTD | DEV FP/h | TEST FP/h |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| count @1s | 99.3 | 23.7 | 38.3 | 80.6 | 36.7 | 3,405.2 | 98.7 | 78.1 | 87.2 | 93.5 | 85.1 | 43.5 | 0.1 | 8.0 |
| count @10s (p) | 100.0 | 34.7 | 51.5 | 53.8 | 42.2 | 3,405.2 | 100.0 | 94.9 | 97.4 | 92.9 | 93.9 | 47.6 | 0.0 | 0.0 |
| count @10s (u) | 100.0 | 34.8 | 51.7 | 53.8 | 42.3 | 3,405.2 | 100.0 | 94.9 | 97.4 | 92.9 | 93.9 | 47.6 | 0.0 | 0.0 |
| count @60s (p) | 100.0 | 36.2 | 53.2 | 36.9 | 36.5 | 3,406.2 | 100.0 | 93.2 | 96.5 | 90.5 | 91.9 | 65.7 | 0.0 | 0.0 |
| count @60s (u) | 80.1 | 39.2 | 52.7 | 33.3 | 36.0 | 3,405.2 | 100.0 | 93.2 | 96.5 | 90.5 | 91.9 | 65.7 | 8.7 | 0.0 |
| rejected_probes @1s (s) | 100.0 | 29.5 | 45.5 | 81.8 | 43.3 | 40.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| rejected_probes @1s (u) | 100.0 | 21.0 | 34.8 | 79.1 | 33.2 | 3,405.2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| rejected_probes @1s (e) | 100.0 | 57.1 | 72.7 | 79.4 | 66.4 | 33.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| rejected_probes @10s (s) | 100.0 | 80.0 | 88.9 | 56.3 | 66.1 | 34.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| rejected_probes @10s (u) | 100.0 | 38.2 | 55.3 | 56.0 | 45.4 | 3,405.2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| rejected_probes @60s | 100.0 | 84.7 | 91.7 | 38.2 | 52.7 | 51.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| behaviour @1s (s) | 100.0 | 48.8 | 65.6 | 43.9 | 46.3 | 40.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| behaviour @1s (u) | 100.0 | 45.3 | 62.3 | 42.2 | 43.7 | 51.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| behaviour @1s (e) | 100.0 | 73.2 | 84.5 | 52.0 | 60.8 | 33.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| behaviour @10s (s) | 100.0 | 83.8 | 91.2 | 49.3 | 62.1 | 34.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| behaviour @10s (u) | 100.0 | 48.7 | 65.5 | 43.9 | 46.2 | 51.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| behaviour @60s | 100.0 | 84.7 | 91.7 | 38.2 | 52.6 | 51.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.0 | 0.0 |
| all @1s | 99.7 | 48.8 | 65.5 | 43.9 | 46.2 | 40.4 | 98.7 | 78.1 | 87.2 | 93.5 | 85.1 | 43.5 | 0.1 | 8.0 |
| all @60s (p) | 100.0 | 84.7 | 91.7 | 38.2 | 52.6 | 51.9 | 100.0 | 93.2 | 96.5 | 90.5 | 91.9 | 65.7 | 0.0 | 0.0 |
| all @60s (u) | 89.7 | 84.7 | 87.1 | 36.6 | 51.1 | 51.9 | 100.0 | 93.2 | 96.5 | 90.5 | 91.9 | 65.7 | 8.7 | 0.0 |

## 2. Wednesday (held out)

| Configuration | P | R | F1 | FP/h | FP s | strict P | strict F1 | recall DoS slowloris | recall DoS Slowhttptest | recall DoS Hulk | recall DoS GoldenEye |
|---|---|---|---|---|---|---|---|---|---|---|---|
| count @1s | 99.3 | 14.8 | 25.8 | 0.4 | 3 | 94.8 | 25.6 | 0.4 | 13.5 | 50.2 | 20.1 |
| count @10s (p) | 100.0 | 21.3 | 35.2 | 0.0 | 0 | 70.2 | 32.7 | 0.1 | 22.2 | 88.2 | 6.2 |
| count @10s (u) | 100.0 | 21.3 | 35.2 | 0.0 | 0 | 70.2 | 32.7 | 0.1 | 22.2 | 88.2 | 6.2 |
| count @60s (p) | 100.0 | 25.0 | 40.0 | 0.0 | 0 | 57.8 | 34.9 | 0.0 | 33.9 | 96.6 | 0.0 |
| count @60s (u) | 93.0 | 25.0 | 39.4 | 6.7 | 57 | 55.4 | 34.5 | 0.0 | 33.9 | 96.6 | 0.0 |
| rejected_probes @1s (s) | 0.0 | 0.0 | 0.0 | 0.1 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes @1s (u) | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes @1s (e) | 0.0 | 0.0 | 0.0 | 0.6 | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes @10s (s) | 0.0 | 0.0 | 0.0 | 1.1 | 9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes @10s (u) | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| rejected_probes @60s | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| behaviour @1s (s) | 97.2 | 9.1 | 16.7 | 0.9 | 8 | 96.9 | 16.7 | 0.0 | 33.6 | 0.2 | 0.0 |
| behaviour @1s (u) | 97.5 | 9.1 | 16.7 | 0.8 | 7 | 97.2 | 16.7 | 0.0 | 33.6 | 0.2 | 0.0 |
| behaviour @1s (e) | 95.9 | 9.1 | 16.6 | 1.4 | 12 | 95.5 | 16.6 | 0.0 | 33.6 | 0.2 | 0.0 |
| behaviour @10s (s) | 94.6 | 9.1 | 16.6 | 1.9 | 16 | 94.2 | 16.6 | 0.0 | 33.6 | 0.2 | 0.0 |
| behaviour @10s (u) | 97.5 | 9.1 | 16.7 | 0.8 | 7 | 97.2 | 16.7 | 0.0 | 33.6 | 0.2 | 0.0 |
| behaviour @60s | 97.5 | 9.1 | 16.7 | 0.8 | 7 | 97.2 | 16.7 | 0.0 | 33.6 | 0.2 | 0.0 |
| all @1s | 98.4 | 22.4 | 36.5 | 1.3 | 11 | 95.3 | 36.3 | 0.4 | 41.3 | 50.4 | 20.1 |
| all @60s (p) | 99.2 | 27.7 | 43.3 | 0.8 | 7 | 59.9 | 37.9 | 0.0 | 43.9 | 96.6 | 0.0 |
| all @60s (u) | 93.0 | 27.7 | 42.7 | 7.6 | 64 | 57.6 | 37.4 | 0.0 | 43.9 | 96.6 | 0.0 |

## 3. Counts behind the strict rule

| Day | Configuration | segment | TP s | FP s | ignored attacker s |
|---|---|---|---|---|---|
| friday | count @1s | dev | 141 | 1 | 33 |
| friday | count @1s | test | 855 | 11 | 48 |
| friday | count @10s (p) | dev | 206 | 0 | 177 |
| friday | count @10s (p) | test | 1039 | 0 | 79 |
| friday | count @10s (u) | dev | 207 | 0 | 178 |
| friday | count @10s (u) | test | 1039 | 0 | 79 |
| friday | count @60s (p) | dev | 215 | 0 | 368 |
| friday | count @60s (p) | test | 1021 | 0 | 107 |
| friday | count @60s (u) | dev | 233 | 58 | 408 |
| friday | count @60s (u) | test | 1021 | 0 | 107 |
| friday | rejected_probes @1s (s) | dev | 175 | 0 | 39 |
| friday | rejected_probes @1s (s) | test | 0 | 0 | 0 |
| friday | rejected_probes @1s (u) | dev | 125 | 0 | 33 |
| friday | rejected_probes @1s (u) | test | 0 | 0 | 0 |
| friday | rejected_probes @1s (e) | dev | 339 | 0 | 88 |
| friday | rejected_probes @1s (e) | test | 0 | 0 | 0 |
| friday | rejected_probes @10s (s) | dev | 475 | 0 | 368 |
| friday | rejected_probes @10s (s) | test | 0 | 0 | 0 |
| friday | rejected_probes @10s (u) | dev | 227 | 0 | 178 |
| friday | rejected_probes @10s (u) | test | 0 | 0 | 0 |
| friday | rejected_probes @60s | dev | 503 | 0 | 813 |
| friday | rejected_probes @60s | test | 0 | 0 | 0 |
| friday | behaviour @1s (s) | dev | 290 | 0 | 370 |
| friday | behaviour @1s (s) | test | 0 | 0 | 0 |
| friday | behaviour @1s (u) | dev | 269 | 0 | 369 |
| friday | behaviour @1s (u) | test | 0 | 0 | 0 |
| friday | behaviour @1s (e) | dev | 435 | 0 | 401 |
| friday | behaviour @1s (e) | test | 0 | 0 | 0 |
| friday | behaviour @10s (s) | dev | 498 | 0 | 513 |
| friday | behaviour @10s (s) | test | 0 | 0 | 0 |
| friday | behaviour @10s (u) | dev | 289 | 0 | 369 |
| friday | behaviour @10s (u) | test | 0 | 0 | 0 |
| friday | behaviour @60s | dev | 503 | 0 | 814 |
| friday | behaviour @60s | test | 0 | 0 | 0 |
| friday | all @1s | dev | 290 | 1 | 370 |
| friday | all @1s | test | 855 | 11 | 48 |
| friday | all @60s (p) | dev | 503 | 0 | 814 |
| friday | all @60s (p) | test | 1021 | 0 | 107 |
| friday | all @60s (u) | dev | 503 | 58 | 814 |
| friday | all @60s (u) | test | 1021 | 0 | 107 |
| wednesday | count @1s | all | 452 | 3 | 22 |
| wednesday | count @10s (p) | all | 651 | 0 | 277 |
| wednesday | count @10s (u) | all | 651 | 0 | 277 |
| wednesday | count @60s (p) | all | 763 | 0 | 558 |
| wednesday | count @60s (u) | all | 763 | 57 | 558 |
| wednesday | rejected_probes @1s (s) | all | 0 | 1 | 0 |
| wednesday | rejected_probes @1s (u) | all | 0 | 0 | 0 |
| wednesday | rejected_probes @1s (e) | all | 0 | 5 | 0 |
| wednesday | rejected_probes @10s (s) | all | 0 | 9 | 0 |
| wednesday | rejected_probes @10s (u) | all | 0 | 0 | 0 |
| wednesday | rejected_probes @60s | all | 0 | 0 | 0 |
| wednesday | behaviour @1s (s) | all | 278 | 8 | 1 |
| wednesday | behaviour @1s (u) | all | 278 | 7 | 1 |
| wednesday | behaviour @1s (e) | all | 278 | 12 | 1 |
| wednesday | behaviour @10s (s) | all | 278 | 16 | 1 |
| wednesday | behaviour @10s (u) | all | 278 | 7 | 1 |
| wednesday | behaviour @60s | all | 278 | 7 | 1 |
| wednesday | all @1s | all | 683 | 11 | 23 |
| wednesday | all @60s (p) | all | 845 | 7 | 559 |
| wednesday | all @60s (u) | all | 845 | 64 | 559 |

## 4. Reproduction checks (pre-registration section 3)

| Configuration | existing label | Friday identical | Wednesday identical |
|---|---|---|---|
| count @1s | count / fixed | yes | yes |
| rejected_probes @60s | only rejected_probes | yes | yes |
| behaviour @60s | behaviour / fixed | yes | yes |

## 5. Thresholds actually run (count rules and rejected_probes; half_open and port_entropy unchanged)

| Configuration | thresholds |
|---|---|
| count @1s | syn_flood > 100; icmp_flood > 100; port_sweep > 20; victim_packet_flood > 400; victim_conn_flood > 32 |
| count @10s (p) | syn_flood > 1000 @10s; icmp_flood > 1000 @10s; port_sweep > 200 @10s; victim_packet_flood > 4000 @10s; victim_conn_flood > 320 @10s |
| count @10s (u) | syn_flood > 1000 @10s; icmp_flood > 1000 @10s; port_sweep > 20 @10s; victim_packet_flood > 4000 @10s; victim_conn_flood > 320 @10s |
| count @60s (p) | syn_flood > 6000 @60s; icmp_flood > 6000 @60s; port_sweep > 1200 @60s; victim_packet_flood > 24000 @60s; victim_conn_flood > 1920 @60s |
| count @60s (u) | syn_flood > 6000 @60s; icmp_flood > 6000 @60s; port_sweep > 20 @60s; victim_packet_flood > 24000 @60s; victim_conn_flood > 1920 @60s |
| rejected_probes @1s (s) | rejected_probes > 1 @1s |
| rejected_probes @1s (u) | rejected_probes > 10 @1s |
| rejected_probes @1s (e) | rejected_probes > 0 @1s |
| rejected_probes @10s (s) | rejected_probes > 2 @10s |
| rejected_probes @10s (u) | rejected_probes > 10 @10s |
| rejected_probes @60s | rejected_probes > 10 @60s |
| behaviour @1s (s) | rejected_probes > 1 @1s |
| behaviour @1s (u) | rejected_probes > 10 @1s |
| behaviour @1s (e) | rejected_probes > 0 @1s |
| behaviour @10s (s) | rejected_probes > 2 @10s |
| behaviour @10s (u) | rejected_probes > 10 @10s |
| behaviour @60s | rejected_probes > 10 @60s |
| all @1s | syn_flood > 100; icmp_flood > 100; port_sweep > 20; victim_packet_flood > 400; victim_conn_flood > 32; rejected_probes > 1 @1s |
| all @60s (p) | syn_flood > 6000 @60s; icmp_flood > 6000 @60s; port_sweep > 1200 @60s; victim_packet_flood > 24000 @60s; victim_conn_flood > 1920 @60s; rejected_probes > 10 @60s |
| all @60s (u) | syn_flood > 6000 @60s; icmp_flood > 6000 @60s; port_sweep > 20 @60s; victim_packet_flood > 24000 @60s; victim_conn_flood > 1920 @60s; rejected_probes > 10 @60s |

## 6. Run times

| Configuration | Friday s | Wednesday s | packets Friday | packets Wednesday |
|---|---|---|---|---|
| count @1s | 17 | 26 | 9,915,501 | 13,705,535 |
| count @10s (p) | 22 | 33 | 9,915,501 | 13,705,535 |
| count @10s (u) | 22 | 33 | 9,915,501 | 13,705,535 |
| count @60s (p) | 22 | 34 | 9,915,501 | 13,705,535 |
| count @60s (u) | 22 | 33 | 9,915,501 | 13,705,535 |
| rejected_probes @1s (s) | 16 | 25 | 9,915,501 | 13,705,535 |
| rejected_probes @1s (u) | 16 | 25 | 9,915,501 | 13,705,535 |
| rejected_probes @1s (e) | 16 | 25 | 9,915,501 | 13,705,535 |
| rejected_probes @10s (s) | 17 | 25 | 9,915,501 | 13,705,535 |
| rejected_probes @10s (u) | 17 | 25 | 9,915,501 | 13,705,535 |
| rejected_probes @60s | 17 | 25 | 9,915,501 | 13,705,535 |
| behaviour @1s (s) | 20 | 30 | 9,915,501 | 13,705,535 |
| behaviour @1s (u) | 21 | 29 | 9,915,501 | 13,705,535 |
| behaviour @1s (e) | 21 | 29 | 9,915,501 | 13,705,535 |
| behaviour @10s (s) | 21 | 29 | 9,915,501 | 13,705,535 |
| behaviour @10s (u) | 21 | 28 | 9,915,501 | 13,705,535 |
| behaviour @60s | 21 | 28 | 9,915,501 | 13,705,535 |
| all @1s | 23 | 27 | 9,915,501 | 13,705,535 |
| all @60s (p) | 28 | 31 | 9,915,501 | 13,705,535 |
| all @60s (u) | 28 | 29 | 9,915,501 | 13,705,535 |

Wall time for all 40 runs: 140 s on 8 processes.

## 7. Exact commands

```
python -m pytest -q                                   # 49 passed at the time (53 now)
python -m experiments.window_matching reproduce       # R2 check -> results/window_matching/r2_reproduction/results.md
python -m experiments.window_matching                 # this file and results.json
```
Machine: the project laptop (macOS, 8 worker processes), Python from the repository's `venv/`.

## 8. Deviations from the pre-registration

- **TTD definition (scoring code bug, fixed before any analysis).** The first run of `window_matching.py` printed
  `score()['windows'][w]['ttd']`, which is the first attacker alert anywhere in the window (+5 s slack), including
  seconds without attacker → victim traffic. The pre-registration (section 4) and Table IV define time to detect as the
  first **true** alert, as `derived_tables.py` computes it. The script was corrected to that definition and all 40 runs
  were repeated. The second run reproduced every P, R and F1 of the first run exactly; only the scan TTD of six rows
  changed (50.9 → 51.9 s: behaviour @1s (u), behaviour @10s (u), behaviour @60s, all @60s (p), all @60s (u); the
  first run's values are kept in no file). No configuration, threshold or criterion was changed.
- No other deviation. All 20 pre-registered configurations ran on both days; none was added, dropped or substituted.
