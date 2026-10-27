#!/bin/bash
# Zeek port-scan baseline on the CICIDS2017 captures.
# Usage: baselines/zeek/run_zeek.sh [default|matched|wednesday_default|default_asshipped|matched_asshipped ...]
#        (no argument = default and matched, in parallel)
# Reads the captures from the data folder ($NIDS_DATA, default <repo>/data) and writes <data>/zeek/out_<job>/.
# Zeek 9.0.0 (Homebrew). policy/misc/scan.zeek is no longer shipped (removed in 6.1), so the copy from the
# last release that shipped it (v6.0.9, tag commit 7a7864f8) is loaded verbatim: scan_v6.0.9_original.zeek.
# sumstats_epoch_compat.zeek restores the v6.0.9 SumStats epoch roll-over that Zeek >= 7.1 dropped for
# SumStats without an epoch_result callback (see that file). The *_asshipped jobs run without it.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
DATA=$(cd "${NIDS_DATA:-$HERE/../../data}" && pwd)
FRI=$DATA/Friday-WorkingHours.pcap
WED=$DATA/Wednesday-workingHours.pcap
mkdir -p "$DATA/zeek"
run() {   # $1 = name, $2 = pcap, $3 = config script, $4 = shim script ("" = Zeek 9 as shipped)
  local out=$DATA/zeek/out_$1
  rm -rf "$out"; mkdir -p "$out"
  ( cd "$out" && /usr/bin/time -p zeek -C -r "$2" \
      "$HERE/scan_v6.0.9_original.zeek" "$HERE/site.zeek" "$HERE/log_suppressed.zeek" ${4:+"$HERE/$4"} "$HERE/$3" \
      > stdout.log 2> stderr.log )
  local rc=$?
  # keep notice.log, scan_suppressed.log and Zeek's own stdout/stderr; the protocol logs are not used
  ( cd "$out" && ls | grep -v -e '^notice.log$' -e '^scan_suppressed.log$' -e '^stderr.log$' -e '^stdout.log$' \
      -e '^conn.log$' | xargs rm -f )
  echo "$1 exit=$rc $(date)" >> "$DATA/zeek/run_status.txt"
}
jobs_=("$@"); [ ${#jobs_[@]} -eq 0 ] && jobs_=(default matched)
for j in "${jobs_[@]}"; do
  case $j in
    default)           run default "$FRI" config_default.zeek sumstats_epoch_compat.zeek & ;;
    matched)           run matched "$FRI" config_matched.zeek sumstats_epoch_compat.zeek & ;;
    wednesday_default) run wednesday_default "$WED" config_default.zeek sumstats_epoch_compat.zeek & ;;
    default_asshipped) run default_asshipped "$FRI" config_default.zeek "" & ;;
    matched_asshipped) run matched_asshipped "$FRI" config_matched.zeek "" & ;;
    *) echo "unknown job $j"; exit 1 ;;
  esac
done
wait
echo ALLDONE >> "$DATA/zeek/run_status.txt"
