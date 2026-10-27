"""
Score Suricata's eve.json alerts with exactly the same per-second protocol as sweep_friday.py
(DEV = port scan segment, TEST = DDoS segment; TP = alert attributed to 172.16.0.1 inside an attack window).
Usage: python3 eval_suricata.py out_et/eve.json [out_custom/eve.json ...]
"""
import os
import datetime
import json
import sys
from collections import Counter

from legacy import sweep_friday as sf  # noqa: E402  (reuses windows, segments and ground truth)
from nids.paths import DATA  # noqa: E402
sf.CACHE = os.path.join(DATA, 'friday.cache')

ATT = sf.ATTACKER


def score(path, only_prefix=None):
    act, hours = sf.active_seconds()
    tp_secs = {'dev': set(), 'test': set()}
    fp_secs = {'dev': set(), 'test': set()}
    sig_tp, sig_fp, fp_src = Counter(), Counter(), Counter()
    first_alert, n, no_src = {}, 0, 0
    with open(path) as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get('event_type') != 'alert':
                continue
            n += 1
            if 'src_ip' not in e:   # decoder/anomaly alerts without an IP header cannot be attributed to a source
                no_src += 1
                continue
            ts = datetime.datetime.fromisoformat(e['timestamp']).timestamp()
            src, sig = e['src_ip'], e['alert']['signature']
            if only_prefix and not sig.startswith(only_prefix):
                continue
            w = sf.window_of(ts) if src == ATT else None
            if w:
                tp_secs[sf.seg(ts)].add(int(ts))
                sig_tp[sig] += 1
                first_alert.setdefault(w, ts - sf.WINDOWS[w][0])
            else:
                fp_secs[sf.seg(ts)].add(int(ts))
                sig_fp[sig] += 1
                fp_src[src] += 1
    out = {'alerts': n, 'no_src': no_src, 'ttd': first_alert, 'sig_tp': sig_tp.most_common(6), 'sig_fp': sig_fp.most_common(6), 'fp_src': fp_src.most_common(5)}
    for s in sf.SEGMENTS:
        tp, pos, fp = len(tp_secs[s] & act[s]), len(act[s]), len(fp_secs[s])
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / pos if pos else 0.0
        out[s] = {'precision': p, 'recall': r, 'f1': 2 * p * r / (p + r) if p + r else 0.0, 'fp_secs': fp, 'fp_per_hour': fp / hours[s], 'tp': tp, 'pos': pos}
    return out


if __name__ == '__main__':
    # --et-only : score only 'ET ' (Emerging Threats attack signatures), ignoring Suricata's own decoder/stream/protocol-anomaly
    #             alerts ('SURICATA ...'), which are parser notices, not attack detections.
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    prefix = 'ET ' if '--et-only' in sys.argv else None
    if '--scan-dos' in sys.argv:      # only the ET categories that target our attacks: ET SCAN* and ET DOS*
        prefix = ('ET SCAN', 'ET DOS')
    res = {}
    for p in args:
        r = score(p, prefix)
        res[p] = r
        d, t = r['dev'], r['test']
        print(f"\n=== {p}{(' [ET SCAN/DOS signatures only]' if isinstance(prefix, tuple) else ' [ET signatures only]') if prefix else ''}: {r['alerts']:,} alerts ({r['no_src']:,} without a source IP, not scored)")
        print(f"  DEV  (port scan): P={d['precision'] * 100:5.1f}% R={d['recall'] * 100:5.1f}% F1={d['f1'] * 100:5.1f}%  FP seconds={d['fp_secs']} ({d['fp_per_hour']:.1f}/h)")
        print(f"  TEST (DDoS)     : P={t['precision'] * 100:5.1f}% R={t['recall'] * 100:5.1f}% F1={t['f1'] * 100:5.1f}%  FP seconds={t['fp_secs']} ({t['fp_per_hour']:.1f}/h)")
        print(f"  time to first alert after window start: { {k: round(v) for k, v in r['ttd'].items()} }")
        print('  top TP signatures:', r['sig_tp'])
        print('  top FP signatures:', r['sig_fp'])
        print('  top FP sources   :', r['fp_src'])
    json.dump(res, open(('suricata_results_scan_dos.json' if isinstance(prefix, tuple) else 'suricata_results_et_only.json') if prefix else 'suricata_results.json', 'w'), indent=1)
