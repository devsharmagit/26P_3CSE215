#!/bin/bash
# Held-out Wednesday run, in two steps (from this code/ directory):
#
#   ./run_wednesday.sh check   # find the PCAP (project folder or ~/Downloads), verify its MD5, move it next to
#                              # the Friday PCAP, build wednesday.cache, print the attacker's activity per minute
#   ./run_wednesday.sh run     # after the windows in days.py match the check output: experiments, figures, report
#
# Do not change any threshold after looking at Wednesday: it is the held-out day. Fixing the attack windows in
# days.py to match the capture is allowed (that is ground truth, not tuning).
set -euo pipefail
cd "$(dirname "$0")"
PY=./venv/bin/python
NAME=Wednesday-workingHours
OUT=results/wednesday

check() {
    for ext in pcap md5; do
        if [ ! -f "../$NAME.$ext" ] && [ -f "$HOME/Downloads/$NAME.$ext" ]; then
            echo "moving ~/Downloads/$NAME.$ext -> ../"
            mv "$HOME/Downloads/$NAME.$ext" ..
        fi
    done
    [ -f "../$NAME.pcap" ] || { echo "../$NAME.pcap not found (still downloading?)"; exit 1; }
    if [ -f "../$NAME.md5" ]; then
        want=$(awk '{print $1}' "../$NAME.md5")
        echo "checking MD5 (reads the whole file, ~1 min)..."
        got=$(md5 -q "../$NAME.pcap")
        [ "$want" = "$got" ] || { echo "MD5 MISMATCH: expected $want, got $got. Download again."; exit 1; }
        echo "MD5 ok ($got)"
    else
        echo "no $NAME.md5 found, skipping the checksum"
    fi
    mkdir -p "$OUT"
    $PY explore_day.py wednesday | tee "$OUT/explore.txt"
    echo
    echo "Saved to $OUT/explore.txt. Compare the attacker's busy minutes with the windows in days.py before 'run'."
}

run() {
    $PY experiments.py wednesday
    $PY make_figures.py wednesday
    $PY main.py analyze -f wednesday.cache --truth wednesday
    echo "Results: $OUT/results.md, figures in $OUT/, report in report/wednesday/report.html"
}

case "${1:-}" in
    check) check ;;
    run) run ;;
    *) echo "usage: $0 check|run"; exit 1 ;;
esac
