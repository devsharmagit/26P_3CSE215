# legacy/ — Phase-1 code (kept for reference)

The first phase of the project built two hard-coded detectors and evaluated them on synthetic traffic and on
CICIDS2017 flow CSVs. The current system (`nids/`, rules as data in `config/rules.yaml`) replaced them. These files
are kept so that the project's history can be followed; they are not used by the paper's experiments, except where
noted.

| File | What it was |
|---|---|
| `rule_engine.py` | Phase-1 static engine (fixed SYN / ICMP / port-scan thresholds). Used by `tests/test_fixes.py`. |
| `adaptive_engine.py` | Phase-1 adaptive engine. `config/legacy_rules.yaml` reproduces it exactly in the new engine (checked by `tests/test_engine.py`); the "legacy AdaptiveRuleEngine" reference row of `results/friday/results.md`. |
| `benchmark.py`, `enhanced_metrics.py`, `evaluate.py` | Phase-1 comparisons of the two engines on the synthetic capture. |
| `cicids_adapter.py`, `cicids_ml_adapter.py`, `evaluate_cicids.py`, `evaluate_cicids_ml.py` | Phase-1 evaluation on CICIDS2017 flow CSVs (see `docs/history/CICIDS_ML_FORMAT_LIMITATION.md` for why packet captures were used instead). |
| `evaluate_friday.py`, `sweep_friday.py`, `perf_friday.py`, `explore_friday.py` | First experiments on the raw Friday capture (before the current scoring). |
| `eval_suricata.py` | First Suricata scoring (old scoring); superseded by `baselines/suricata/eval_suricata_v2.py`. |
| `make_figures.py` | Figures of the first paper draft. |
| `generate_pcap.py` | Small synthetic test capture of Phase 1. |
| `run_wednesday.sh` | One-off helper used to download-check and first run the Wednesday capture (old layout). |
| `outputs/` | Outputs of the scripts above (sweep results, first Suricata scores, a CSV fixture). |

Run any of them from the repository root as a module, e.g. `python -m legacy.benchmark`. `explore_friday.py` and
`generate_pcap.py` are plain scripts that run on import.
