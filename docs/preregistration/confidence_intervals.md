# Pre-registration: bootstrap confidence intervals (revision 3, step 4)

Written and committed on 2026-10-26 on branch `submission-ready`, before any per-second output was extracted and before
any interval was computed. Deviations, if any, are recorded in `code/results/confidence_intervals/results.md` under
"Deviations".

## 1. Data: per-second outcomes

No per-second outputs are stored in the existing results files (they hold totals only). The configurations below are
therefore re-run with the **unchanged** engine and `rules.yaml` (no engine change), and for each run and each scored
segment the script stores, for every integer second of that segment, four 0/1 values:

- `pos`: the second is a positive (attacker → victim traffic inside an in-scope window), as in `experiments.Truth`;
- `tp`: a positive second covered by an attacker detection, as in `experiments.score`;
- `fp`: a false-alarm second of that segment, as in `experiments.score`;
- `ign`: an attacker alert-second inside an in-scope window without attacker → victim traffic (the seconds the strict
  rule counts as false alarms), assigned to the segment the window starts in, as in `window_matching.strict`.

Segments: Friday DEV (first packet → 15:40 ADT), Friday TEST (15:40 → last packet), Wednesday (whole capture). The
grid of a segment is every integer second from the floor of its start to the floor of its end.

**Reproduction check (must pass before any bootstrap):** the sums of `pos`, `tp`, `fp` per segment must equal the
stored `positives`, `tp` and `fp_secs` in `results/{friday,wednesday}/results.json` (Table III configurations) and
`results/window_matching/results.json` (window configurations), and the sum of `ign` must equal the stored ignored
counts in `results/window_matching/results.json`. Any difference stops the step.

Configurations (fixed engine, fixed thresholds as already published):
- Table III: count / behaviour / all × fixed / adaptive, and all / adaptive without freeze (7), on Friday and
  Wednesday.
- Window table: count @1s (= count / fixed), behaviour @1s (s), count @60s (p), count @60s (u), behaviour @60s
  (= behaviour / fixed), as defined in `paper_completion/revision2/PREREGISTRATION.md`; Friday and Wednesday.

## 2. Statistics

- F1 from per-second sums: default F1 = 2·TP / (POS + TP + FP); strict F1 = 2·TP / (POS + TP + FP + IGN). These are
  algebraically equal to 2PR/(P+R) with P = TP/(TP+FP) (strict: TP/(TP+FP+IGN)) and R = TP/POS, i.e. the paper's
  definitions. If the denominator is 0, F1 = 0.
- **Moving-block bootstrap over seconds**, separately within each segment. For a segment of N seconds and block length
  L: k = ⌈N/L⌉ blocks with start indices drawn uniformly from {0, …, N − L}, concatenated and truncated to N seconds.
- **Primary block length L = 60 s**; sensitivity L = 30 s and L = 300 s.
- **B = 2000** resamples; random generator `numpy.random.default_rng(20261026)`; one fixed draw of block starts per
  (segment, L) shared by all configurations, so that every difference is **paired** (same resampled seconds for both
  configurations).
- 95% **percentile** intervals: the 2.5th and 97.5th percentiles of the B replicate values (`numpy.percentile`,
  default linear interpolation). Point estimates are the published values (full sample).
- All values in percent, printed to one decimal like every other results file.

## 3. Quantities

Levels (both scoring rules, all three segments): F1 of every configuration in §1.

Paired differences (both scoring rules):
- **(a) Measure effect, behaviour F1 − count F1.** Friday DEV: unmatched (behaviour / fixed − count / fixed),
  matched 1 s (behaviour @1s (s) − count @1s), matched 60 s (behaviour @60s − count @60s (p), and − count @60s (u)).
  Also Friday TEST and Wednesday, unmatched (expected negative: count beats behaviour there).
- **(b) Policy effect, fixed F1 − adaptive F1**, for count, behaviour and all rules, in each of the three segments.
- **(c) Freeze effect, all / adaptive − all / adaptive without freeze**, Friday TEST (the DDoS; primary). Also
  reported for Wednesday and Friday DEV.
- **(d) Added here: "the measure moves F1 more than the policy"** (the title claim). Per segment,
  D = |M| − max over families |fixed − adaptive|, with M = behaviour / fixed − count / fixed, computed inside each
  resample.

## 4. Interpretation (decided now)

- A difference is **"supported"** if its 95% interval at the primary block length (60 s) **excludes zero**. Results at
  30 s and 300 s are reported as sensitivity and do not change the label.
- **STOP-FLAG (from the brief):** if any interval for (a), (b) or (c) includes zero, it is reported in
  `paper_completion/revision3/DECISIONS_NEEDED.md` with proposed wording in `PROPOSED_CLAIM_CHANGES.md`, and the
  abstract and conclusion claims are not changed until a human approves.
- Noted in advance, so that it is not read as an excuse afterwards: for (b) the paper's claim is that the policy moves
  F1 little and that adaptive is never higher. An interval for (b) that includes zero does not contradict that claim,
  but it does mean the paper must not say or imply that fixed thresholds are *significantly* better. Where two
  configurations give identical per-second outcomes, their difference is exactly 0 in every resample and the interval
  is [0, 0]. The STOP-FLAG applies to (b) all the same.
- Scope of the intervals, to be stated in the paper: they describe the per-second sampling variability within these
  captures. They do not cover variability across attacks, attackers or datasets (one scan, one DDoS, four DoS attacks).

## 5. Commands (to be run after this file is committed)

```
cd code
./venv/bin/python ci_per_second.py     # re-runs the configurations, writes results/confidence_intervals/per_second/,
                                       # and runs the reproduction check
./venv/bin/python bootstrap_ci.py      # reads per_second/, writes results/confidence_intervals/results.md + .json
./venv/bin/python -m pytest -q         # includes test_bootstrap.py (toy example)
```
