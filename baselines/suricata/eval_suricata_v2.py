"""
T03b: re-score the existing Suricata outputs (out_et/eve.json, out_custom/eve.json; Suricata 8.0.7, run 5 Oct 2026)
with the CURRENT ground truth and scoring of experiments.py (Truth + score, victim-only positives), so the Suricata
numbers are comparable with every other result. legacy/eval_suricata.py (legacy sweep_friday scoring) and its JSON files
are kept in legacy/.

Alert -> detection: (alert timestamp, alert src_ip, score 1), the same attribution as eval_suricata.py; alerts without
a source IP (decoder events) cannot be attributed and are skipped and counted.

    python -m baselines.suricata.eval_suricata_v2      # reads <data>/suricata/out_*/eve.json, writes results/suricata_rescored/
"""
import datetime
import json
import os

from experiments.grid import Truth, pct, score
from nids.days import DAYS
from nids.paths import DATA, ROOT

VIEWS = [  # (label, eve.json, signature filter)
    ('ET Open (52,768 rules), every alert', 'out_et/eve.json', None),
    ('ET Open, ET signatures only', 'out_et/eve.json', ('ET ',)),
    ('ET Open, ET SCAN / ET DOS signatures only', 'out_et/eve.json', ('ET SCAN', 'ET DOS')),
    ('custom threshold rules (4)', 'out_custom/eve.json', None),
]


def load(path, prefixes):
    dets, n, no_src = [], 0, 0
    with open(os.path.join(DATA, 'suricata', path)) as f:
        for line in f:
            if '"event_type":"alert"' not in line:
                continue
            e = json.loads(line)
            n += 1
            if 'src_ip' not in e:
                no_src += 1
                continue
            sig = e['alert']['signature']
            if prefixes and not sig.startswith(prefixes):
                continue
            ts = datetime.datetime.fromisoformat(e['timestamp']).timestamp()
            dets.append((ts, e['src_ip'], 1, [sig]))
    return dets, n, no_src


def main():
    truth = Truth(DAYS['friday'], DAYS['friday'].capture())
    L = ['# T03b: Suricata re-scored with the current scoring (Friday)', '',
         'Suricata 8.0.7 (`out_et/suricata.log`: "52768 rules successfully loaded"; `out_custom/suricata.log`: 4 rules),',
         'HOME_NET 192.168.10.0/24. Scored with `experiments.Truth` + `experiments.score` (victim-only positives, 5 s slack).',
         'Reproduce: `python -m baselines.suricata.eval_suricata_v2` (needs <data>/suricata/out_et/ and out_custom/ from baselines/suricata/run_suricata.sh).', '',
         '| View | alerts (scored) | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS | TTD PortScan (s) | TTD DDoS (s) |',
         '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|']
    out = {}
    for label, path, pref in VIEWS:
        dets, n, no_src = load(path, pref)
        r = score(truth, dets, 1)
        out[label] = {'alerts_total': n, 'no_src': no_src, 'scored': len(dets), **r}
        c = [label, f'{len(dets):,}']
        for s in ('dev', 'test'):
            m = r['segments'][s]
            c += [pct(m['precision']), pct(m['recall']), pct(m['f1']), f"{m['fp_per_hour']:.1f}"]
        c += [pct(r['windows'][w]['recall']) for w in ('PortScan', 'DDoS')]
        c += ['–' if r['windows'][w]['ttd'] is None else f"{r['windows'][w]['ttd']:.1f}" for w in ('PortScan', 'DDoS')]
        L.append('| ' + ' | '.join(c) + ' |')
        print(label, 'done', flush=True)
    L += ['', 'Alerts without a source IP (not attributable, skipped): ' +
          '; '.join(f"{k}: {v['no_src']:,} of {v['alerts_total']:,}" for k, v in out.items())]
    d = os.path.join(ROOT, 'results', 'suricata_rescored')
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'results.md'), 'w').write('\n'.join(L) + '\n')
    json.dump(out, open(os.path.join(d, 'results.json'), 'w'), indent=1, default=str)
    print('wrote', d)


if __name__ == '__main__':
    main()
