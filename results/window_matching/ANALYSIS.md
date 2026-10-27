# Window-matching experiment: analysis against the pre-registered criteria (R4)

Data: `results.md` / `results.json` in this folder. Criteria: `docs/preregistration/window_matching.md` §5,
committed (6525bee) before any run. All F1 values are Friday DEV (scan) F1 as printed (one decimal); differences are
differences of the printed values.

## 1. The four primary comparisons

| Matched window | Scoring | behaviour family | count family | behaviour exceeds count? |
|---|---|---|---|---|
| 1 s | default | 65.6 (behaviour @1s (s)) | 38.3 (count @1s) | yes |
| 1 s | strict | 46.3 | 36.7 | yes |
| 60 s | default | 91.7 (behaviour @60s) | 53.2 (p) / 52.7 (u) | yes (exceeds both) |
| 60 s | strict | 52.6 | 36.5 (p) / 36.0 (u) | yes (exceeds both) |

Verdict rule, applied in the pre-registered order:
1. "Mainly a window effect" requires count @60s (either variant) ≥ behaviour @60s under the strict rule:
   36.5 and 36.0 vs 52.6 → **not met**.
2. "Measure effect survives" requires behaviour > count in all four comparisons → **met** (4 of 4).

**Verdict: the measure effect survives.**

## 2. How large the measure effect is, unmatched vs matched (behaviour F1 − count F1, Friday scan)

| Comparison | default scoring | strict scoring |
|---|---|---|
| Unmatched (paper): behaviour @60s vs count @1s | 91.7 − 38.3 = **53.4** | 52.6 − 36.7 = **15.9** |
| Matched at 1 s: behaviour @1s (s) vs count @1s | 65.6 − 38.3 = **27.3** | 46.3 − 36.7 = **9.6** |
| Matched at 10 s: behaviour @10s (s) vs count @10s (p) / (u) | 91.2 − 51.5 = 39.7 / 91.2 − 51.7 = 39.5 | 62.1 − 42.2 = 19.9 / 62.1 − 42.3 = 19.8 |
| Matched at 60 s: behaviour @60s vs count @60s (p) / (u) | 91.7 − 53.2 = 38.5 / 91.7 − 52.7 = 39.0 | 52.6 − 36.5 = 16.1 / 52.6 − 36.0 = 16.6 |

What this says, plainly:
- **Under the paper's default scoring, part of the headline gap was the window.** Matching the windows shrinks the
  effect from 53.4 points to 27.3 (at 1 s) or 38.5–39.0 (at 60 s). Count rules gain from a longer window
  (38.3 → 53.2 / 52.7 at 60 s); rejected_probes loses from a shorter one (behaviour family 91.7 → 65.6 at 1 s).
  The 38.3 → 91.7 contrast is therefore an upper bound on the measure effect, not a window-free estimate.
- **Under strict scoring the effect is about the same size matched at 60 s (16.1–16.6) as unmatched (15.9), and smaller
  at 1 s (9.6).** Strict scoring already penalises long windows, and it penalises them in both families: count @60s
  (p) has 100.0% default DEV precision but 36.9% strict precision (368 attacker alert-seconds without attack traffic).
- For reference, the threshold-policy effect in Table III (fixed − adaptive F1, Friday scan) is 0.0 for count rules and
  12.1 for behaviour rules under default scoring (91.7 − 79.6), and 0.0 and 2.3 under strict scoring (52.6 − 50.3,
  `scoring_check/results.md`). The smallest matched measure effect (9.6, strict, 1 s) is still larger than the policy
  effect under the same scoring (2.3). The default-scoring 1 s effect (27.3) is larger than the default policy
  effect (12.1).

## 3. Robustness: secondary pre-registered variants (not used for the verdict)

| Variant | default: behaviour vs count | strict: behaviour vs count | verdict would change? |
|---|---|---|---|
| rejected_probes 1 s, unscaled (> 10) | 62.3 vs 38.3 | 43.7 vs 36.7 | no |
| rejected_probes 1 s, brief's example (> 0) | 84.5 vs 38.3 | 60.8 vs 36.7 | no |
| rejected_probes 10 s, unscaled (> 10) vs count @10s (p)/(u) | 65.5 vs 51.5 / 51.7 | 46.2 vs 42.2 / 42.3 | no (10 s is not a verdict window) |

The rule **alone** at 1 s is weaker: rejected_probes @1s (s) reaches 45.5 / 43.3 (default / strict), above the count
family (38.3 / 36.7), but the unscaled rejected_probes @1s (u) alone reaches only 34.8 / 33.2, **below** the count family.
At 1 s the behaviour family's advantage therefore depends on half_open and port_entropy as well as on rejected_probes;
recall that those two rules are not windowless (half_open tracks connections for 30 s; port_entropy halves its counts
every second).

## 4. Time to detect the scan

Count rules first detect the scan at 3,405.2 s after the window start at 1 s and 10 s and at 3,406.2 s / 3,405.2 s at
60 s (p) / (u): even port_sweep > 20 distinct ports in 60 s does not fire before the 998-port sweep at 14:51, because the
early Nmap phases probe only 5 TCP ports. rejected_probes detects it after 40.4 s at 1 s (s), 34.3 s at 10 s (s) and
51.9 s at 60 s. The time-to-detect gap is therefore a measure effect at every window tested.

## 5. Other effects of the window (reported because they matter, although outside the verdict)

- **Count rules also gain on the DDoS from longer windows.** Friday TEST F1 87.2 (1 s) → 97.4 (10 s) → 96.5 (60 s),
  with the first true DDoS alert later (43.5 → 47.6 → 65.7 s) and strict TEST F1 85.1 → 93.9 → 91.9. The 1 s default
  of the count rules is not their best window on Friday.
- **Wednesday (held out).** Longer count windows raise Wednesday F1 (count 25.8 at 1 s → 35.2 at 10 s → 40.0 / 39.4 at
  60 s (p) / (u); all rules 36.5 at 1 s → 43.3 / 42.7 at 60 s), mainly Hulk recall (50.2 → 96.6), but strict precision
  falls (count 94.8 → 57.8 / 55.4). Count rules beat behaviour rules on Wednesday at every window (behaviour family
  16.6–16.7 at every window), as in Table III.
- **False alarms from the unchanged-threshold port_sweep at 60 s.** count @60s (u) raises 58 false-alarm seconds in
  Friday DEV (8.7 per hour) and 57 on Wednesday (6.7 per hour); count @60s (p) raises none.

## 6. Wednesday false alarms of rejected_probes at short windows

As expected, the scaled-down thresholds at short windows raise more false alarms on Wednesday than the 60 s default
(which raises none):

| rejected_probes alone | Wednesday false-alarm seconds | per hour |
|---|---|---|
| 1 s, > 1 (s) | 1 | 0.1 |
| 1 s, > 10 (u) | 0 | 0.0 |
| 1 s, > 0 (e) | 5 | 0.6 |
| 10 s, > 2 (s) | 9 | 1.1 |
| 10 s, > 10 (u) | 0 | 0.0 |
| 60 s, > 10 (default) | 0 | 0.0 |

In the behaviour family this raises Wednesday false alarms from 0.8 per hour (60 s) to 0.9 (1 s (s)), 1.4 (1 s (e)) and
1.9 (10 s (s)). Wednesday has no scan, so these runs test false alarms only, not detection.

## 7. Consequences for the paper

- The verdict is "survives", so per the brief no STOP flag is raised and the headline claim may stay. It must be
  qualified: the unmatched 38.3 → 91.7 contrast overstates the measure effect under default scoring; at matched
  windows it is 27.3 (1 s) to 38.5 (60 s) F1 points, and 9.6 to 16.1 under strict scoring.
- The "Measure vs. window" threat is now tested. What remains: the distinct-port threshold scaling (both variants
  reported; neither changes the verdict); half_open and port_entropy are not windowed; and the rejected_probes design and
  the window thresholds were derived from a rule tuned on Friday (the rule is still in-sample on Friday).
