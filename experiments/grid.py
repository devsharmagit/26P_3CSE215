"""
Main experiment: does it matter more WHAT a rule measures, or HOW its threshold is set?

Every configuration is a variant of rules.yaml run through the same engine (engine.py), so the only
thing that changes between two cells is the rule family or the threshold policy:

                        fixed thresholds     adaptive thresholds (EMA + freeze)
    count rules               A                        B
    behaviour rules           C                        D
    all rules                 E                        F

plus ablations (each rule alone, all minus one rule, adaptive without the freeze safeguard), the
transparent score used as an alert filter (score >= k), and the legacy AdaptiveRuleEngine settings as a
reference row (config/legacy_rules.yaml, reproduces legacy/adaptive_engine.py exactly).

    python -m experiments.grid friday        # ~2 min on 8 processes (needs the Friday capture or its cache in data/)
    python -m experiments.grid synthetic     # seconds
    python -m experiments.grid wednesday     # held-out day (needs the Wednesday capture in data/)

Scoring (same as sweep_friday.py): the unit is one second. A positive is a second in which the attacker
sent traffic (to the day's attack target, if days.py names one) inside an in-scope attack window. A detection attributed to the attacker inside a window
(+5 s slack) covers that second (TP); any other detection makes its second a false-alarm second (FP).
Detections from the attacker inside out-of-scope windows are ignored.
Results go to results/<day>/results.json and results/<day>/results.md.
"""
import json
import os
import sys
import time
from collections import defaultdict
from multiprocessing import Pool

from nids import pcapng_reader as pr
from nids.days import DAYS, SYNTHETIC_OWNER
from nids.engine import RuleEngine
from nids.rule_set import load_rules

from nids.paths import LEGACY_RULES as LEGACY, ROOT, RULES
SLACK = 5.0
FAMILIES = {'count': ['count'], 'behaviour': ['behaviour'], 'all': ['count', 'behaviour']}
SCORE_LEVELS = (1, 2, 3)


def build_jobs():
    """(label, group, spec). spec: rules file + RuleSet.variant() arguments + optional overrides."""
    jobs = []
    for fam, kinds in FAMILIES.items():
        for pol in ('fixed', 'adaptive'):
            jobs.append((f'{fam} / {pol}', 'grid', {'kinds': kinds, 'policy': pol}))
    jobs.append(('all / adaptive, no freeze', 'safeguard', {'policy': 'adaptive', 'set': {'freeze_seconds': 0.0}}))
    ids = [r.id for r in load_rules(RULES).rules]
    for rid in ids:
        jobs.append((f'only {rid}', 'single', {'ids': [rid], 'policy': 'fixed'}))
    for rid in ids:
        jobs.append((f'all minus {rid}', 'minus', {'exclude': [rid], 'policy': 'fixed'}))
    jobs.append(('legacy AdaptiveRuleEngine', 'reference', {'file': LEGACY}))
    # sensitivity of the new rule (its default 10 probes / 60 s was chosen after looking at Friday)
    for win in (30, 60, 120):
        for val in (3, 5, 10, 20, 40):
            jobs.append((f'rejected_probes > {val} in {win} s', 'sensitivity',
                         {'ids': ['rejected_probes'], 'policy': 'fixed',
                          'set': {'value': float(val), 'params': {'window_seconds': win, 'direction': 'inbound'}}}))
    return jobs


def make_rule_set(spec):
    rs = load_rules(spec.get('file', RULES))
    rs = rs.variant(policy=spec.get('policy'), kinds=spec.get('kinds'), ids=spec.get('ids'),
                    exclude=spec.get('exclude', ()))
    for r in rs.rules:
        for k, v in spec.get('set', {}).items():
            setattr(r, k, v)
    return rs


# ---------------------------------------------------------------------------------- ground truth
class Truth:
    """Attacker-active seconds per window, segments and their durations for one day."""

    def __init__(self, day, path):
        self.day = day
        first = last = None
        att_int = {int.from_bytes(bytes(int(x) for x in a.split('.')), 'big') for a in day.attackers}
        tgt_int = {int.from_bytes(bytes(int(x) for x in a.split('.')), 'big') for a in day.targets}
        raw = defaultdict(list)  # attacker -> packet timestamps (to the targets, if the day names them)
        for rec in pr.iter_any(path):
            ts = rec[0]
            if first is None:
                first = ts
            last = ts
            if rec[1] in att_int and (not tgt_int or rec[2] in tgt_int):
                raw[pr.ip_to_str(rec[1])].append(ts)
        self.first, self.last = first, last
        off = first if day.relative else 0.0
        tol = 1.0 if day.relative else 0.0
        self.windows = [(w.name, w.start + off - tol, w.end + off + tol, w.in_scope) for w in day.windows]
        self.owner = {w.name: (SYNTHETIC_OWNER[w.name] if day.relative else None) for w in day.windows}
        self.active = defaultdict(set)  # window -> seconds the window's attacker was sending
        for a, stamps in raw.items():
            for name, s, e, in_scope in self.windows:
                if in_scope and self.owner[name] in (None, a):
                    self.active[name].update(int(t) for t in stamps if s <= t <= e)
        segs = [(n, (st + off) if st is not None else first) for n, st in day.segments]
        self.segments = segs
        self.hours = {}
        for i, (n, st) in enumerate(segs):
            end = segs[i + 1][1] if i + 1 < len(segs) else last
            self.hours[n] = max(end - st, 1e-9) / 3600.0
        self.slack = tol if day.relative else SLACK

    def segment(self, t):
        name = self.segments[0][0]
        for n, st in self.segments:
            if t >= st:
                name = n
        return name

    def window_of(self, src, t):
        """(window name, in_scope) if `src` is attacking in a window at t, else None."""
        if src not in self.day.attackers:
            return None
        for name, s, e, in_scope in self.windows:
            if s <= t <= e + self.slack and self.owner[name] in (None, src):
                return name, in_scope
        return None


def score(truth, dets, min_score=1):
    """dets: list of (time, src, score, rule_ids). Per-segment and per-window metrics."""
    tp_units = defaultdict(set)          # window -> seconds covered
    fp_secs = defaultdict(set)           # segment -> false-alarm seconds
    first_tp = {}
    fp_rules = defaultdict(int)
    fp_src = defaultdict(set)
    n = 0
    for t, src, sc, rules in dets:
        if sc < min_score:
            continue
        n += 1
        w = truth.window_of(src, t)
        if w is None:
            fp_secs[truth.segment(t)].add(int(t))
            fp_src[src].add(int(t))
            for r in rules:
                fp_rules[r] += 1
        elif w[1]:
            tp_units[w[0]].add(int(t))
            first_tp.setdefault(w[0], t)
    top = sorted(fp_src.items(), key=lambda kv: -len(kv[1]))
    out = {'detections': n, 'fp_by_rule': dict(fp_rules), 'fp_hosts': len(fp_src),
           'fp_benign_hosts': sum(1 for h in fp_src if h not in truth.day.attackers),
           'fp_top_sources': [(h, len(v)) for h, v in top[:8]], 'windows': {}, 'segments': {}}
    seg_tp, seg_pos = defaultdict(int), defaultdict(int)
    for name, s, e, in_scope in truth.windows:
        if not in_scope:
            continue
        act = truth.active[name]
        hit = tp_units[name] & act
        out['windows'][name] = {'positives': len(act), 'covered': len(hit),
                                'recall': len(hit) / len(act) if act else 0.0,
                                'ttd': (first_tp[name] - s) if name in first_tp else None}
        for sec in act:
            seg_pos[truth.segment(sec)] += 1
        for sec in hit:
            seg_tp[truth.segment(sec)] += 1
    for seg, _ in truth.segments:
        tp, pos, fp = seg_tp[seg], seg_pos[seg], len(fp_secs[seg])
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / pos if pos else 0.0
        out['segments'][seg] = {'tp': tp, 'positives': pos, 'fp_secs': fp, 'fp_per_hour': fp / truth.hours[seg],
                                'precision': p, 'recall': r, 'f1': 2 * p * r / (p + r) if p + r else 0.0}
    if truth.day.relative:
        found = {SYNTHETIC_OWNER[w] for w, v in out['windows'].items() if v['covered']}
        out['attackers_detected'] = len(found)
    return out


# ---------------------------------------------------------------------------------- running
_TRUTH = {}


def run_job(args):
    day_name, path, (label, group, spec) = args
    if (day_name, path) not in _TRUTH:
        _TRUTH[(day_name, path)] = Truth(DAYS[day_name], path)
    truth = _TRUTH[(day_name, path)]
    dets = []
    eng = RuleEngine(make_rule_set(spec), on_detection=lambda d: dets.append((d.time, d.src, d.score, d.rule_ids)))
    t0 = time.time()
    for rec in pr.iter_any(path):
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    eng.flush()
    res = {'label': label, 'group': group, 'seconds': time.time() - t0, 'packets': eng.packets,
           'by_score': {k: score(truth, dets, k) for k in SCORE_LEVELS}}
    res.update(res['by_score'][1])
    return res


def pct(x):
    return f'{x * 100:.1f}'


def to_markdown(day, truth, results):
    segs = [s for s, _ in truth.segments]
    wins = [n for n, s, e, i in truth.windows if i]
    by = {r['label']: r for r in results}
    L = [f'# Results: {day.name}', '', day.note, '',
         f'Positives (attacker-active seconds): ' + ', '.join(f'{w} {len(truth.active[w])}' for w in wins), '']

    def row(r, extra=''):
        cells = [r['label'] + extra]
        for s in segs:
            m = r['segments'][s]
            cells += [pct(m['precision']), pct(m['recall']), pct(m['f1']), f"{m['fp_per_hour']:.1f}"]
        cells += [pct(r['windows'][w]['recall']) for w in wins]
        if 'attackers_detected' in r:
            cells.append(f"{r['attackers_detected']}/5")
        return '| ' + ' | '.join(cells) + ' |'

    head = ['Configuration'] + [f'{s.upper()} {k}' for s in segs for k in ('P', 'R', 'F1', 'FP/h')] + [f'recall {w}' for w in wins]
    if day.relative:
        head.append('attackers found')
    hdr = ['| ' + ' | '.join(head) + ' |', '|' + '---|' * len(head)]

    L += ['## 1. Rule family x threshold policy', '',
          'Rows change WHAT is measured, the two rows of each family change only HOW the threshold is set.', '']
    L += hdr + [row(by[f'{fam} / {pol}']) for fam in FAMILIES for pol in ('fixed', 'adaptive')]
    L += ['', '### Compact view (F1 per segment)', '']
    L += ['| Rule family | ' + ' | '.join(f'{p} {s.upper()}' for p in ('fixed', 'adaptive') for s in segs) + ' |',
          '|---|' + '---|' * (2 * len(segs))]
    for fam in FAMILIES:
        L.append(f'| {fam} | ' + ' | '.join(pct(by[f'{fam} / {p}']['segments'][s]['f1']) for p in ('fixed', 'adaptive') for s in segs) + ' |')
    L += ['', '## 2. Safeguard: adaptive thresholds without the baseline freeze', '']
    L += hdr + [row(by['all / adaptive']), row(by['all / adaptive, no freeze'])]
    L += ['', '## 3. Each rule alone (fixed thresholds)', ''] + hdr + [row(r) for r in results if r['group'] == 'single']
    L += ['', '## 4. All rules minus one (fixed thresholds)', ''] + hdr + [row(by['all / fixed'], ' (none removed)')] + \
         [row(r) for r in results if r['group'] == 'minus']
    L += ['', '## 5. Transparent score as an alert filter (all rules)', '',
          'score = sum of the weights of the rules that fired for the host in that second (all weights are 1, so',
          'score = number of rules that agree). Only detections with score >= k are kept.', '']
    L += hdr
    for lab in ('all / fixed', 'all / adaptive'):
        for k in SCORE_LEVELS:
            r = dict(by[lab])
            r.update(by[lab]['by_score'][k])
            r['label'] = f'{lab}, score >= {k}'
            L.append(row(r))
    sens = [r for r in results if r['group'] == 'sensitivity']
    if sens:
        L += ['', '## 5b. Sensitivity of the rejected-probes rule (rule alone, fixed)', '',
              'Its default (> 10 rejected probes in 60 s) was chosen after looking at the Friday attacker, so this table',
              'shows how much the result depends on that choice.', ''] + hdr + [row(r) for r in sens]
    L += ['', '## 6. Reference', '', 'Legacy AdaptiveRuleEngine settings (legacy_rules.yaml; reproduces adaptive_engine.py exactly).', '']
    L += hdr + [row(by['legacy AdaptiveRuleEngine'])]
    L += ['', '## False alarms (all / fixed)', '',
          f"Hosts with a false-alarm second: {by['all / fixed']['fp_hosts']} "
          f"(of which not attackers: {by['all / fixed']['fp_benign_hosts']}); "
          f"top: {by['all / fixed']['fp_top_sources']}", '',
          f"Detections per rule in false-alarm seconds: {by['all / fixed']['fp_by_rule']}"]
    return '\n'.join(L) + '\n'


def main():
    day_name = sys.argv[1] if len(sys.argv) > 1 else 'friday'
    day = DAYS[day_name]
    path = day.capture()
    jobs = build_jobs()
    print(f'{day_name}: {len(jobs)} configurations on {os.path.basename(path)}', flush=True)
    t0 = time.time()
    truth = Truth(day, path)
    for w in truth.active:
        print(f'  positives {w}: {len(truth.active[w])} s')
    results = []
    workers = min(8, os.cpu_count() or 1)
    with Pool(workers) as pool:
        for i, r in enumerate(pool.imap_unordered(run_job, [(day_name, path, j) for j in jobs]), 1):
            results.append(r)
            print(f'  [{i}/{len(jobs)}] {r["label"]:<34} ' + '  '.join(
                f"{s} F1 {pct(m['f1'])} FP/h {m['fp_per_hour']:.1f}" for s, m in r['segments'].items()) +
                f'  ({time.time() - t0:.0f}s)', flush=True)
    order = {j[0]: i for i, j in enumerate(jobs)}
    results.sort(key=lambda r: order[r['label']])
    out = os.path.join(ROOT, 'results', day_name)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'results.json'), 'w') as f:
        json.dump({'day': day_name, 'capture': os.path.basename(path), 'note': day.note,
                   'positives': {w: len(s) for w, s in truth.active.items()},
                   'hours': truth.hours, 'results': results}, f, indent=1)
    md = to_markdown(day, truth, results)
    with open(os.path.join(out, 'results.md'), 'w') as f:
        f.write(md)
    print(f'\nwrote results/{day_name}/results.json and results.md ({time.time() - t0:.0f}s)')


if __name__ == '__main__':
    main()
