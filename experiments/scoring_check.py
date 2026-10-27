"""
Reviewer check (T11/T12): how many attacker alert-seconds the per-second scoring ignores, and the precision if they
were counted as false alarms instead.

score() (experiments.py) marks a detection on the attacker inside an attack window (+5 s slack) as covering that second;
if the attacker sent no traffic to the victim in that second, the second is not a positive, so it is neither a hit nor a
false alarm. Rules that keep alerting after the probes stop (rejected_probes counts over 60 s) produce many such seconds.

    python -m experiments.scoring_check        # ~2 min; writes results/scoring_check/results.md
"""
import os
from multiprocessing import Pool

from nids import pcapng_reader as pr
from nids.days import DAYS
from nids.engine import RuleEngine
from experiments.grid import Truth, make_rule_set, pct, score

from nids.paths import ROOT  # noqa: E402  (repository root)
CONFIGS = [('only rejected_probes', {'ids': ['rejected_probes'], 'policy': 'fixed'}),
           ('count / fixed', {'kinds': ['count'], 'policy': 'fixed'}),
           ('behaviour / fixed', {'kinds': ['behaviour'], 'policy': 'fixed'}),
           ('all / fixed', {'kinds': ['count', 'behaviour'], 'policy': 'fixed'}),
           ('count / adaptive', {'kinds': ['count'], 'policy': 'adaptive'}),
           ('behaviour / adaptive', {'kinds': ['behaviour'], 'policy': 'adaptive'}),
           ('all / adaptive', {'kinds': ['count', 'behaviour'], 'policy': 'adaptive'})]


def run(cfg):
    label, spec = cfg
    path = DAYS['friday'].capture()
    truth = Truth(DAYS['friday'], path)
    dets = []
    eng = RuleEngine(make_rule_set(spec), on_detection=lambda d: dets.append((d.time, d.src, d.score, d.rule_ids)))
    for rec in pr.iter_any(path):
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    eng.flush()
    r = score(truth, dets, 1)
    rows = []
    for wname, seg in (('PortScan', 'dev'), ('DDoS', 'test')):
        act = truth.active[wname]
        att = {int(t) for t, s, _sc, _r in dets if (w := truth.window_of(s, t)) and w[0] == wname}
        tp, ign = att & act, att - act
        fp = r['segments'][seg]['fp_secs']
        strict_p = len(tp) / (len(tp) + fp + len(ign)) if tp or fp or ign else 0.0
        rec = r['segments'][seg]['recall']
        strict_f1 = 2 * strict_p * rec / (strict_p + rec) if strict_p + rec else 0.0
        rows.append((label, wname, len(att), len(tp), len(ign), pct(r['segments'][seg]['precision']), pct(strict_p),
                     pct(r['segments'][seg]['f1']), pct(strict_f1)))
    return rows


def main():
    with Pool(len(CONFIGS)) as pool:
        out = [row for rows in pool.map(run, CONFIGS) for row in rows]
    L = ['# Scoring check: attacker alert-seconds the per-second scoring ignores (Friday)', '',
         'Reproduce: `python -m experiments.scoring_check`. "Ignored" = seconds with a detection on 172.16.0.1 inside an',
         'attack window (+5 s slack) in which the attacker sent nothing to the victim: neither hit nor false alarm in score().',
         '"Strict precision" counts them as false alarms (segment of that attack).', '',
         'F1 uses the segment recall (unchanged) with each precision. Segment = DEV for PortScan, TEST for DDoS.', '',
         '| Configuration | Attack | attacker alert-seconds | hits | ignored | precision (as reported) | strict precision | F1 (as reported) | strict F1 |',
         '|---|---|---|---|---|---|---|---|---|']
    L += [f'| {a} | {b} | {c:,} | {d:,} | {e:,} | {f} | {g} | {h} | {i} |' for a, b, c, d, e, f, g, h, i in out]
    d = os.path.join(ROOT, 'results', 'scoring_check')
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'results.md'), 'w').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
