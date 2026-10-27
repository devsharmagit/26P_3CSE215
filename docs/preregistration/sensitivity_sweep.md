# T04 Best-vs-best and sensitivity (Friday only)

**Purpose:** show whether *any* adaptive setting beats the best fixed setting, so that "adaptive gave no gain" is not an artefact of one default setting, or of the adaptive floor (audit E1).

**Inputs:** `code/friday.cache`, `code/rules.yaml`, `code/days.py`, `code/experiments.py` (`Truth`, `score`; unchanged).

## Design (written 22 Oct BEFORE any run; not changed afterwards)
- **Families:** count (5 rules), behaviour (3 rules), all (8 rules). Only the rules' thresholds change. The engine, scoring, windows and rule definitions stay as they are.
- **Fixed grid:** one strictness scale `s` ∈ {0.25, 0.5, 0.75, 1, 1.5, 2, 3}, applied to every rule in the family:
  - count rules and `rejected_probes`: value × s
  - `port_entropy`: value × s (bits)
  - `half_open`: 1 − 0.2 / s, clipped to [0.5, 0.99] (so s = 1 gives the default 0.8, and a larger s is stricter)
- **Adaptive grid:** floor scale `f` ∈ {0.25, 0.5, 1} (the same mapping as `s`, applied to the floor value) × multiplier level 1–5:
  - counts and `rejected_probes`: m ∈ {1.5, 2, 3, 4, 6}
  - ratio-like rules (`half_open`, `port_entropy`): m ∈ {1.05, 1.1, 1.25, 1.5, 2}, matched to the counts list by level
  - alpha = 0.2 and freeze = 60 s (defaults)
  - f < 1 lets the adaptive policy be **more** sensitive than the fixed default for quiet hosts. This answers the floor confound.
- **Runs:** 3 families × (7 fixed + 15 adaptive) = 66 runs on Friday.
- **Selection protocol** (the Friday DEV/TEST split, unchanged): pick the best setting per family and policy by **DEV F1**, then report its TEST F1. Also report the **oracle** maximum of each policy on each segment separately.
- **Question answered:** per family and segment, is max F1 over the adaptive grid > max F1 over the fixed grid? Any positive margin counts as "yes", and is logged in DECISIONS_NEEDED.md (stop-and-flag b).
- **Wednesday:** not used for anything here. A later, optional step may run the DEV-selected configurations on Wednesday unchanged.
- **Figure:** F1 vs fixed scale `s`, and F1 vs multiplier level (one line per floor), for count and behaviour rules, DEV and TEST. 300 dpi, black/grey with distinct markers and line styles, so it reads in greyscale.

**Steps:** write `code/sensitivity.py` (it imports `Truth` and `score` from `experiments.py`), run it, and write `code/results/sensitivity/{results.json,results.md,fig_sensitivity.png}`.

**Outputs:** `code/results/sensitivity/`

**Acceptance criteria:** 66 runs complete. The tables list every setting with DEV/TEST P/R/F1/FP-per-hour. The best-vs-best table and the oracle table exist. The figure is at 300 dpi. The 37 tests pass.

**Status:** DONE (22 Oct)

**Result summary:** 66/66 runs, 405 s. Consistency check: "floor=1, m-level=3" reproduces the default adaptive rows of `results/friday/results.md` exactly (count 38.3/87.1, behaviour 79.6/0.0, all 79.6/87.1).
- **No adaptive setting beats the best fixed setting** on any family or segment (`code/results/sensitivity/results.md` §2: margins −0.1, +0.0, +0.0, +0.0, −7.5, +0.0, and the code found no positive margin). Lowering the adaptive floor to 0.25× or 0.5× makes adaptive *equal* to fixed at best: with a low floor and a low multiplier, adaptive behaves like a fixed threshold at the lower floor.
- Held-out protocol (§1): DEV-selected all/fixed (s=0.75) gives DEV 92.7 / TEST 89.5. DEV-selected all/adaptive (floor 0.5, level 1) gives DEV 85.2 / TEST 90.2, but with 18.7 / 23.2 FP per hour against fixed's 1.8 / 10.9.
- With the default floor, count/adaptive at multiplier levels 4–5 drops TEST F1 to ≈0 (`results.md` §3). **Mechanism verified (22 Oct, a baseline trace for 192.168.10.50 with count/adaptive floor 1, m = 4):** before the DDoS the victim's pps baseline is about 22. In the first DDoS seconds the rate stays below the 400 floor, so the rule does not fire and the baseline is not frozen. It then tracks the flood (814 at 15:57:08) and the threshold rises to 2,500–3,400 pps (4 × baseline), above the actual flood rate of about 200–1,700 pps. Only 1 detection is raised during the whole DDoS. So the freeze only protects the baseline if the rule fires *before* the baseline has absorbed the attack. Saved: `code/baseline_trace.py` → `code/results/sensitivity/baseline_trace.md` (per-minute baseline, threshold and freeze state; 1 attacker detection in the DDoS window).
- Defaults are NOT changed (that would be tuning). The paper reports the sensitivity only.
- Figure: `code/results/sensitivity/fig_sensitivity.png` (300 dpi, greyscale).
