#!/bin/bash
# Runs Suricata offline over the Friday capture twice: ET Open only, then the custom threshold rules only.
# Reads <data>/Friday-WorkingHours.pcap ($NIDS_DATA, default <repo>/data) and writes <data>/suricata/out_et, out_custom.
# ET Open rule file: $ET_RULES (default: the Homebrew path used for the paper).
HERE=$(cd "$(dirname "$0")" && pwd)
DATA=$(cd "${NIDS_DATA:-$HERE/../../data}" && pwd)
PCAP=$DATA/Friday-WorkingHours.pcap
OUT=$DATA/suricata
for run in et custom; do
  mkdir -p "$OUT/out_$run"
  if [ $run = et ]; then RULES="-S ${ET_RULES:-/opt/homebrew/var/lib/suricata/rules/suricata.rules}"; else RULES="-S $HERE/custom.rules"; fi
  /usr/bin/time -p suricata -c "$HERE/suricata_alerts_only.yaml" $RULES -r "$PCAP" -l "$OUT/out_$run" -k none --runmode single > "$OUT/out_$run/stdout.log" 2>&1
  echo "$run finished: $(wc -l < "$OUT/out_$run/eve.json") eve lines" >> "$OUT/run_status.txt"
done
echo ALLDONE >> "$OUT/run_status.txt"
