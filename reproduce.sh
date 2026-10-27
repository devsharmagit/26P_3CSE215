#!/bin/bash
# One command per item of the paper. Run from anywhere; uses ./venv if it exists, otherwise python3.
# The CICIDS2017 captures must be in data/ (or set NIDS_DATA); see data/README.md.
#   ./reproduce.sh tests | demo | table1 | table2 | table3 | table4 | table5 | table6 | strict | fig1 | fig2 | all
set -e
cd "$(dirname "$0")"
if [ -x venv/bin/python ]; then PY="$PWD/venv/bin/python"; else PY=python3; fi
case "$1" in
  tests)  $PY -m pytest -q ;;
  demo)   $PY main.py rules
          $PY main.py detect -f tests/data/large_evaluation_dataset.pcap --max-print 5
          $PY main.py analyze -f tests/data/large_evaluation_dataset.pcap ;;
  table1) $PY main.py rules ;;                                                  # rule set
  table2) $PY -m experiments.grid friday && $PY -m experiments.grid wednesday ;; # main grid (+ ablations, legacy row)
  table3) $PY -m experiments.window_matching reproduce && $PY -m experiments.window_matching ;;  # matched windows
  table4) $PY -m experiments.ci_per_second && $PY -m experiments.bootstrap_ci ;;                # bootstrap intervals
  table5) $PY -m experiments.derived_tables                                    # our rows + time to detect
          baselines/zeek/run_zeek.sh default matched
          $PY -m baselines.zeek.eval_zeek friday default=zeek/out_default matched=zeek/out_matched
          baselines/suricata/run_suricata.sh
          $PY -m baselines.suricata.eval_suricata_v2 && $PY -m experiments.ttd_check ;;
  table6) $PY -m experiments.derived_tables && $PY -m experiments.slow_dos_check ;;           # Wednesday per attack
  strict) $PY -m experiments.scoring_check ;;                                  # strict-scoring check (Section V-A)
  fig1)   $PY -m experiments.sensitivity && $PY -m experiments.latex_figures ;;
  fig2)   $PY -m experiments.paper_figures && $PY -m experiments.latex_figures ;;
  all)    for t in tests table1 table2 table3 table4 table6 strict fig1 fig2; do "$0" $t; done ;;
  *)      echo "usage: $0 tests|demo|table1|table2|table3|table4|table5|table6|strict|fig1|fig2|all"; exit 2 ;;
esac
