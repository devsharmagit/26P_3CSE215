# results/

Every number in the paper comes from a file in this folder. Each `results.md` says which command produced it.
These files were produced before the repository was reorganised (2026-10-27); their numbers are unchanged, and
the commands in them were updated to the current layout. `revision3_check/` and `window_matching/r2_reproduction/`
re-ran the main configurations after the reorganisation and found every result identical.

| Paper item | Folder | Main file(s) |
|---|---|---|
| Table II (main grid), Friday | `friday/` | `results.md`, `results.json` (also each rule alone, all-minus-one, score filter, rejected_probes sensitivity, legacy reference row) |
| Table II (main grid), Wednesday | `wednesday/` | `results.md`, `results.json` |
| Table III (matched windows) | `window_matching/` | `results.md`, `ANALYSIS.md` (verdict against the pre-registered criteria), `r2_reproduction/` |
| Table IV (bootstrap intervals) | `confidence_intervals/` | `results.md`, `results.json`, `per_second/` (per-second outcomes) |
| Table V (Zeek, Suricata, time to detect) | `zeek_baseline/`, `suricata_rescored/`, `time_to_detect/`, `ttd_check/` | `results.md` in each |
| Table VI (Wednesday per attack) | `wednesday_2x2/` | `results.md`, `slow_dos_check.md` |
| Strict scoring (Section V-A) | `scoring_check/` | `results.md` |
| Fig. 1 (sensitivity sweep, Section V-B) | `sensitivity/` | `results.md`, `results.json`, `fig_sensitivity.png` |
| Fig. 2 (DDoS trace, Section V-C) | `sensitivity/` | `trace_per_second.csv`, `trace_summary.md`, `baseline_trace.md` |
| Scan phases (Section V-D) | `friday_scan_phases/` | `results.md` |
| Throughput (Section IV-B) | `throughput/` | `results.md` |
| Final figures | `figures/` | `fig_sensitivity.pdf`, `fig_trace.pdf` (vector, as in the paper) |
| Synthetic data | `synthetic/` | run of the grid on the synthetic capture |
| Reproduction check | `revision3_check/` | `table3_reproduction.md` |
