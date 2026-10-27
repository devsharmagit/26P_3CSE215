# Pre-registration: window-matching experiment (revision 2, step R1)

Written and committed on 2026-10-26 on branch `final-revision`, **before** the window parameter was implemented
and before any run. Nothing below may be changed after the first run; any deviation is recorded in
`code/results/window_matching/results.md` under "Deviations" with the reason.

## 0. Question

`rejected_probes` aggregates over a sliding 60 s window; the count rules use the engine's 1 s window. The paper's
headline (scan F1 38.3 → 91.7 when moving from count to behaviour rules) therefore changes two things at once: the
**measure** and the **window length**. This experiment matches the windows and asks whether behaviour rules still
beat count rules on the Friday scan when both look at the same amount of time.

## 1. Window semantics (fixed now)

- The engine still steps and reports in 1 s windows (`settings.window_seconds: 1.0`); alerts keep their 1 s time
  stamps, so scoring is unchanged.
- A rule may set `window_seconds: W` (new, per rule). For a **count** measure with `W` larger than the engine
  window, the measured value at each 1 s step is computed over the events with time stamp in
  `[t_end − W, t_end)`, where `t_end` is the time stamp of the first packet after the current 1 s window. This is the
  same anchor `rejected_probes` already uses for its sliding window, so both families slide the same way.
  - `syn_rate`, `icmp_rate`: SYN-only / ICMP packets the source sent in the last W s.
  - `distinct_ports`: distinct destination ports of the source's SYN-only packets in the last W s.
  - `victim_pps`, `victim_conn_rate`: service-port packets / SYN-only packets received by the protected host in
    the last W s. The alert is attributed to the source that sent most service-port packets to that host **in the
    same W s** (today: in the same 1 s window).
- A rule without `window_seconds` (or with `W` equal to the engine window) uses the existing per-window code path,
  unchanged. **Count rules at 1 s are therefore the existing rules**, not a re-implementation.
- `rejected_probes` already has `params.window_seconds` (default 60). It is set to 1, 10 or 60.
- `half_open` and `port_entropy` are **not changed**: they are a ratio and an entropy, not counts per window, and have
  no window length to scale. Note that they are not memoryless: `half_open_ratio` tracks connections for up to the
  30 s connection timeout and `port_entropy` halves its port counts every window. So the "1 s behaviour family"
  below means "rejected_probes at 1 s, the two other behaviour rules unchanged". This caveat goes into the paper.

## 2. Thresholds (decided now, applied mechanically)

All runs use the **fixed** policy. Operators stay as in `rules.yaml` (`>` for every count rule and for
`rejected_probes`).

### 2a. Rate-type counts: proportional, `v_W = v_1 × W`

| Rule | measure | v at 1 s (existing) | v at 10 s | v at 60 s |
|---|---|---|---|---|
| syn_flood | syn_rate | > 100 | > 1,000 | > 6,000 |
| icmp_flood | icmp_rate | > 100 | > 1,000 | > 6,000 |
| victim_packet_flood | victim_pps | > 400 | > 4,000 | > 24,000 |
| victim_conn_flood | victim_conn_rate | > 32 | > 320 | > 1,920 |

### 2b. Distinct-count measure (port_sweep): two variants, both reported, neither preferred

| Variant | 1 s (existing) | 10 s | 60 s |
|---|---|---|---|
| (p) proportional, `v_1 × W` | > 20 | > 200 | > 1,200 |
| (u) unchanged, `v_1` | > 20 | > 20 | > 20 |

At 1 s both variants are the same rule.

### 2c. rejected_probes at W

Rule from the brief: `v_W = v_60 × W / 60`, rounded **up** to the nearest integer, minimum 1, with `v_60 = 10`.

| W | v_60 × W / 60 | rounded up, min 1 | rule (s = scaled, primary) | unscaled variant (u) |
|---|---|---|---|---|
| 1 s | 0.1667 | 1 | **> 1** (≥ 2 refusals in 1 s) | > 10 |
| 10 s | 1.6667 | 2 | **> 2** (≥ 3 refusals in 10 s) | > 10 |
| 60 s | 10 | 10 | **> 10** (existing) | > 10 (same rule) |

**Discrepancy in the brief, resolved now.** The brief's example says "1 s → > 0, i.e. ≥ 1 refusal". That does not follow
from the stated formula (which gives 1, i.e. "> 1"). We apply the formula as written for the primary rule, and also
run the brief's example as a third pre-registered variant, **(e) 1 s, > 0**. The 10 s example (> 2) matches the formula.

## 3. Configurations (exactly these; 20 per day, Friday and Wednesday)

Count family = syn_flood, icmp_flood, port_sweep, victim_packet_flood, victim_conn_flood.
Behaviour family = half_open, port_entropy, rejected_probes.

| # | Label | Rules | Windows / thresholds |
|---|---|---|---|
| 1 | count @1s | count family | existing (1 s) — must reproduce Table III count/fixed |
| 2 | count @10s (p) | count family | 10 s; 2a; port_sweep > 200 |
| 3 | count @10s (u) | count family | 10 s; 2a; port_sweep > 20 |
| 4 | count @60s (p) | count family | 60 s; 2a; port_sweep > 1,200 |
| 5 | count @60s (u) | count family | 60 s; 2a; port_sweep > 20 |
| 6 | rejected_probes @1s (s) | rejected_probes alone | 1 s, > 1 |
| 7 | rejected_probes @1s (u) | rejected_probes alone | 1 s, > 10 |
| 8 | rejected_probes @1s (e) | rejected_probes alone | 1 s, > 0 |
| 9 | rejected_probes @10s (s) | rejected_probes alone | 10 s, > 2 |
| 10 | rejected_probes @10s (u) | rejected_probes alone | 10 s, > 10 |
| 11 | rejected_probes @60s | rejected_probes alone | existing — must reproduce "only rejected_probes" |
| 12 | behaviour @1s (s) | behaviour family | rejected_probes 1 s, > 1 |
| 13 | behaviour @1s (u) | behaviour family | rejected_probes 1 s, > 10 |
| 14 | behaviour @1s (e) | behaviour family | rejected_probes 1 s, > 0 |
| 15 | behaviour @10s (s) | behaviour family | rejected_probes 10 s, > 2 |
| 16 | behaviour @10s (u) | behaviour family | rejected_probes 10 s, > 10 |
| 17 | behaviour @60s | behaviour family | existing — must reproduce Table III behaviour/fixed |
| 18 | all @1s | count @1s + behaviour @1s (s) | as 1 + 12 |
| 19 | all @60s (p) | count @60s (p) + behaviour @60s | as 4 + 17 |
| 20 | all @60s (u) | count @60s (u) + behaviour @60s | as 5 + 17 |

Rows 1, 11 and 17 are reproduction checks: if any of them differs from the existing results files by any amount, the
run stops and the cause is recorded in `DECISIONS_NEEDED.md`.

Adaptive thresholds are not part of this experiment.

## 4. Scoring and what is reported

Two scoring rules, both applied to every configuration:

- **Default** = `experiments.score()` (the paper's per-second rule): an attacker alert in an attack window (+5 s slack)
  in a second without attacker → victim traffic counts as neither hit nor false alarm.
- **Strict** = `scoring_check.py`'s rule: those alert-seconds count as false alarms of the segment of that attack.
  Strict precision = TP / (TP + FP + ignored); F1 uses the unchanged recall. On Wednesday (one segment) the ignored
  seconds of all four in-scope windows are added.

Reported per configuration:
- Friday DEV (scan): P, R, F1 under both rules; time to detect (first true alert, s after window start).
- Friday TEST (DDoS): P, R, F1 under both rules; time to detect.
- Wednesday (held out): P, R, F1 and false-alarm seconds per hour under the default rule; P and F1 under the strict
  rule. Wednesday false-alarm seconds per hour are the same under both rules (strict adds only attacker seconds
  inside attack windows), and are reported once.
- Values printed to one decimal, as in all existing results files.

## 5. Interpretation criteria (decided now)

"Friday scan F1" = Friday DEV F1. Comparisons use the one-decimal printed values; equal printed values are a tie, and
a tie is **not** "exceeds".

Primary comparisons (the verdict uses only these):
- **Matched at 1 s:** behaviour @1s (s) [row 12] vs count @1s [row 1].
- **Matched at 60 s:** behaviour @60s [row 17] vs count @60s. Because neither port_sweep variant is preferred, the
  behaviour family must exceed **both** count @60s (p) [row 4] and count @60s (u) [row 5] (i.e. the better of the two).

Each comparison is made under the default and under the strict rule (4 comparisons in total). Verdict, applied in this
order:

1. **"Mainly a window effect"** if count @60s (either variant) matches or beats behaviour @60s under the **strict** rule.
2. **"Measure effect survives"** if behaviour exceeds count in all 4 comparisons (1 s and 60 s, default and strict).
3. **"Partly a window effect"** otherwise (the effect survives at one matched window but not the other, or under only
   one scoring rule).

Also reported, but **not** used for the verdict:
- The size of the measure effect (behaviour F1 − count F1) unmatched (behaviour @60s vs count @1s, the paper's
  comparison) and matched (at 1 s, at 10 s, at 60 s), under both rules.
- The same comparisons with the secondary rejected_probes variants (u) and (e) at 1 s and (u) at 10 s, as a robustness
  line ("the verdict would / would not change under variant …").
- Wednesday false alarms of rejected_probes at 1 s and 10 s (rows 6–10), expected to be higher than at 60 s with the
  lower thresholds; reported whatever they are.
- Whether the all-rules configurations at matched windows (rows 18–20) change the Friday DDoS result.

## 6. Commands (to be run in step R3)

```
cd code
./venv/bin/python window_matching.py      # all 20 configurations x {friday, wednesday}; writes results/window_matching/
```

Before R3: `./venv/bin/python -m pytest -q`, and `./venv/bin/python experiments.py friday`-equivalent reruns of the
default all/fixed and all/adaptive configurations must reproduce Table III exactly (step R2, written to a new folder,
never over the existing results).
