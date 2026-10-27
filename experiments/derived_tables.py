"""
T02 / T05: per-attack view of the 2x2 (+ no freeze) and time to detect, for Friday and Wednesday.

Re-runs the seven main configurations of experiments.py UNCHANGED (same rules.yaml, same thresholds, same
Truth/score) and keeps the individual detections, which results/<day>/results.json does not store. It checks that
the overall numbers equal results/<day>/results.json, then derives:
  * per-attack precision / recall / F1: TP = attack seconds covered, FP = false-alarm seconds whose time lies inside
    that attack's own span [first attack second, last attack second + 5 s slack]
  * time to detect: first true detection minus (a) the window start in days.py and (b) the first attack second
  * throughput: packets / engine seconds per run (8 runs in parallel; this is not single-process peak speed)

    python -m experiments.derived_tables          # ~3 min on 8 processes
Writes results/wednesday_2x2/results.md, results/time_to_detect/results.md, results/throughput/results.md (+ .json).
"""
import json
import os
import time
from multiprocessing import Pool

from nids import pcapng_reader as pr
from nids.days import DAYS
from nids.engine import RuleEngine
from experiments.grid import SLACK, Truth, make_rule_set, pct, score

from nids.paths import ROOT  # noqa: E402  (repository root)
CONFIGS = [(f'{fam} / {pol}', {'kinds': kinds, 'policy': pol})
           for fam, kinds in (('count', ['count']), ('behaviour', ['behaviour']), ('all', ['count', 'behaviour']))
           for pol in ('fixed', 'adaptive')]
CONFIGS.append(('all / adaptive, no freeze', {'policy': 'adaptive', 'set': {'freeze_seconds': 0.0}}))
_TRUTH = {}


def truth_for(day):
    if day not in _TRUTH:
        _TRUTH[day] = Truth(DAYS[day], DAYS[day].capture())
    return _TRUTH[day]


def run(args):
    day, (label, spec) = args
    truth = truth_for(day)
    dets = []
    eng = RuleEngine(make_rule_set(spec), on_detection=lambda d: dets.append((d.time, d.src, d.score, d.rule_ids)))
    t0 = time.time()
    for rec in pr.iter_any(DAYS[day].capture()):
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    eng.flush()
    secs = time.time() - t0
    overall = score(truth, dets, 1)
    per = {}
    for name, s, e, in_scope in truth.windows:
        if not in_scope or not truth.active[name]:
            continue
        act = truth.active[name]
        lo, hi = min(act), max(act) + SLACK
        tp, fp, first = set(), set(), None
        for t, src, _sc, _r in dets:
            w = truth.window_of(src, t)
            if w is not None and w[0] == name and int(t) in act:
                tp.add(int(t))
                first = t if first is None else min(first, t)
            elif w is None and lo <= t <= hi:
                fp.add(int(t))
        p = len(tp) / (len(tp) + len(fp)) if tp or fp else 0.0
        r = len(tp) / len(act)
        per[name] = {'positives': len(act), 'tp': len(tp), 'fp_secs_in_span': len(fp), 'precision': p, 'recall': r,
                     'f1': 2 * p * r / (p + r) if p + r else 0.0, 'window_start': s, 'first_attack_second': min(act),
                     'ttd_from_window_start': (first - s) if first is not None else None,
                     'ttd_from_first_attack_second': (first - min(act)) if first is not None else None}
    return {'day': day, 'label': label, 'segments': overall['segments'], 'windows_overall': overall['windows'],
            'per_attack': per, 'packets': eng.packets, 'seconds': secs}


def check_against_stored(results):
    """The overall numbers must equal results/<day>/results.json (same code, same data)."""
    bad = []
    for day in ('friday', 'wednesday'):
        stored = {r['label']: r for r in json.load(open(os.path.join(ROOT, 'results', day, 'results.json')))['results']}
        for r in results:
            if r['day'] != day:
                continue
            for seg, m in r['segments'].items():
                if abs(m['f1'] - stored[r['label']]['segments'][seg]['f1']) > 1e-9:
                    bad.append((day, r['label'], seg))
    return bad


def fmt_s(x):
    return '–' if x is None else f'{x:.1f}'


def main():
    jobs = [(d, c) for d in ('friday', 'wednesday') for c in CONFIGS]
    t0 = time.time()
    with Pool(min(8, os.cpu_count() or 1)) as pool:
        results = list(pool.imap(run, jobs))
    bad = check_against_stored(results)
    cmd = '`python -m experiments.grid wednesday && python -m experiments.derived_tables`'
    note_ok = ('Consistency check: overall P/R/F1 of every row equal `results/<day>/results.json` exactly.' if not bad
               else f'CONSISTENCY CHECK FAILED for {bad}')

    # ---- T02: Wednesday 2x2 per attack
    wed = [r for r in results if r['day'] == 'wednesday']
    attacks = list(wed[0]['per_attack'])
    L = ['# T02: Wednesday (held-out) 2x2 + no-freeze, per attack', '',
         'Exact Friday thresholds (rules.yaml unchanged); nothing was chosen on Wednesday. Reproduce: ' + cmd, note_ok, '',
         'Per-attack precision counts the false-alarm seconds inside that attack\'s own span (first to last attack second + 5 s).',
         'Overall = whole capture (08:42-17:10 ADT), day-wide false-alarm seconds.', '',
         '| Configuration | overall P | overall R | overall F1 | FP/h | ' + ' | '.join(f'{a} P / R / F1' for a in attacks) + ' |',
         '|---|---|---|---|---|' + '---|' * len(attacks)]
    for r in wed:
        m = r['segments']['all']
        L.append(f"| {r['label']} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['f1'])} | {m['fp_per_hour']:.1f} | " +
                 ' | '.join(f"{pct(r['per_attack'][a]['precision'])} / {pct(r['per_attack'][a]['recall'])} / {pct(r['per_attack'][a]['f1'])}"
                            for a in attacks) + ' |')
    by = {r['label']: r['segments']['all']['f1'] for r in wed}
    L += ['', '## Answers', '',
          f"- Measure vs threshold: count {pct(by['count / fixed'])} -> all {pct(by['all / fixed'])} F1 (fixed); "
          f"fixed vs adaptive: count {pct(by['count / fixed'])} vs {pct(by['count / adaptive'])}, "
          f"behaviour {pct(by['behaviour / fixed'])} vs {pct(by['behaviour / adaptive'])}, all {pct(by['all / fixed'])} vs {pct(by['all / adaptive'])}.",
          f"- Freeze: all / adaptive {pct(by['all / adaptive'])} vs without freeze {pct(by['all / adaptive, no freeze'])} F1.", '']
    out = os.path.join(ROOT, 'results', 'wednesday_2x2')
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, 'results.md'), 'w').write('\n'.join(L) + '\n')
    json.dump(wed, open(os.path.join(out, 'results.json'), 'w'), indent=1)

    # ---- T05: time to detect
    L = ['# T05: time to first true detection, per attack', '', 'Reproduce: ' + cmd, note_ok, '',
         'Two reference points: (a) the window start in days.py (Friday: CIC schedule minute; Wednesday: exact first attack',
         'packet), (b) the first second in which the attacker sent traffic to the target in that window. "–" = never detected.', '',
         '| Day | Attack | Configuration | TTD from window start (s) | TTD from first attack second (s) | recall |', '|---|---|---|---|---|---|']
    for r in results:
        if r['label'] not in ('all / fixed', 'all / adaptive', 'count / fixed', 'behaviour / fixed'):
            continue
        for a, v in r['per_attack'].items():
            L.append(f"| {r['day']} | {a} | {r['label']} | {fmt_s(v['ttd_from_window_start'])} | "
                     f"{fmt_s(v['ttd_from_first_attack_second'])} | {pct(v['recall'])} |")
    out = os.path.join(ROOT, 'results', 'time_to_detect')
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, 'results.md'), 'w').write('\n'.join(L) + '\n')

    # ---- throughput
    L = ['# Throughput of the rule engine (pure Python)', '', 'Reproduce: ' + cmd,
         'Each run = one configuration over the whole cached capture, 8 runs in parallel on one Apple Silicon laptop;',
         'engine time only (cache reading + engine), excluding the ground-truth pass.', '',
         '| Day | Configuration | packets | seconds | packets/s |', '|---|---|---|---|---|']
    for r in results:
        L.append(f"| {r['day']} | {r['label']} | {r['packets']:,} | {r['seconds']:.1f} | {r['packets'] / r['seconds']:,.0f} |")
    rates = [r['packets'] / r['seconds'] for r in results]
    L += ['', f'Range over these runs: {min(rates):,.0f} to {max(rates):,.0f} packets/s.']
    out = os.path.join(ROOT, 'results', 'throughput')
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, 'results.md'), 'w').write('\n'.join(L) + '\n')
    print(note_ok, f'({time.time() - t0:.0f}s)')


if __name__ == '__main__':
    main()
