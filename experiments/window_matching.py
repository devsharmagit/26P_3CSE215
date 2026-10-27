"""
Revision 2: window-matching experiment (pre-registered in docs/preregistration/window_matching.md).

rejected_probes counts refusals over a sliding 60 s window, the count rules use 1 s windows. This runs count rules and
rejected_probes / the behaviour family at matched window lengths (1, 10, 60 s), with thresholds fixed by the
pre-registration, and scores every run under the paper's per-second rule and the strict rule of scoring_check.py.

    python -m experiments.window_matching reproduce   # R2: Table III configs must equal results/{friday,wednesday}
    python -m experiments.window_matching             # R3: the 20 pre-registered configs x {friday, wednesday}

Writes results/window_matching/ (never the existing results folders).
"""
import json
import os
import sys
import time
from multiprocessing import Pool

from nids import pcapng_reader as pr
from nids.days import DAYS
from nids.engine import RuleEngine
from experiments.grid import Truth, make_rule_set, pct, score

from nids.paths import ROOT  # noqa: E402  (repository root)
OUT = os.path.join(ROOT, 'results', 'window_matching')
DAY_NAMES = ('friday', 'wednesday')
COUNT, BEHAVIOUR = ['count'], ['behaviour']
RATE_RULES = {'syn_flood': 100, 'icmp_flood': 100, 'victim_packet_flood': 400, 'victim_conn_flood': 32}
PORT_SWEEP = 20


def count_at(w, port_sweep):
    """Per-rule overrides for the count family at window w (pre-registration 2a/2b); w = 1 is the existing rule."""
    if w == 1:
        return {}
    per = {rid: {'window_seconds': float(w), 'value': float(v * w)} for rid, v in RATE_RULES.items()}
    per['port_sweep'] = {'window_seconds': float(w), 'value': float(PORT_SWEEP * w if port_sweep == 'p' else PORT_SWEEP)}
    return per


def rejected_at(w, value):
    """rejected_probes at window w with threshold value (pre-registration 2c); w = 60, value 10 is the existing rule."""
    if w == 60 and value == 10:
        return {}
    return {'rejected_probes': {'value': float(value), 'params': {'window_seconds': w, 'direction': 'inbound'}}}


# pre-registration section 3: (label, kinds, ids, per-rule overrides)
CONFIGS = [
    ('count @1s', COUNT, None, count_at(1, 'p')),
    ('count @10s (p)', COUNT, None, count_at(10, 'p')),
    ('count @10s (u)', COUNT, None, count_at(10, 'u')),
    ('count @60s (p)', COUNT, None, count_at(60, 'p')),
    ('count @60s (u)', COUNT, None, count_at(60, 'u')),
    ('rejected_probes @1s (s)', None, ['rejected_probes'], rejected_at(1, 1)),
    ('rejected_probes @1s (u)', None, ['rejected_probes'], rejected_at(1, 10)),
    ('rejected_probes @1s (e)', None, ['rejected_probes'], rejected_at(1, 0)),
    ('rejected_probes @10s (s)', None, ['rejected_probes'], rejected_at(10, 2)),
    ('rejected_probes @10s (u)', None, ['rejected_probes'], rejected_at(10, 10)),
    ('rejected_probes @60s', None, ['rejected_probes'], rejected_at(60, 10)),
    ('behaviour @1s (s)', BEHAVIOUR, None, rejected_at(1, 1)),
    ('behaviour @1s (u)', BEHAVIOUR, None, rejected_at(1, 10)),
    ('behaviour @1s (e)', BEHAVIOUR, None, rejected_at(1, 0)),
    ('behaviour @10s (s)', BEHAVIOUR, None, rejected_at(10, 2)),
    ('behaviour @10s (u)', BEHAVIOUR, None, rejected_at(10, 10)),
    ('behaviour @60s', BEHAVIOUR, None, rejected_at(60, 10)),
    ('all @1s', COUNT + BEHAVIOUR, None, {**count_at(1, 'p'), **rejected_at(1, 1)}),
    ('all @60s (p)', COUNT + BEHAVIOUR, None, {**count_at(60, 'p'), **rejected_at(60, 10)}),
    ('all @60s (u)', COUNT + BEHAVIOUR, None, {**count_at(60, 'u'), **rejected_at(60, 10)}),
]
# rows that must equal an existing result exactly (label here -> label in results/<day>/results.json)
REPRODUCES = {'count @1s': 'count / fixed', 'rejected_probes @60s': 'only rejected_probes', 'behaviour @60s': 'behaviour / fixed'}
# R2: the Table III configurations
TABLE3 = [(f'{fam} / {pol}', kinds, None, {}, pol, {}) for fam, kinds in
          (('count', COUNT), ('behaviour', BEHAVIOUR), ('all', COUNT + BEHAVIOUR)) for pol in ('fixed', 'adaptive')] + \
         [('all / adaptive, no freeze', None, None, {}, 'adaptive', {'freeze_seconds': 0.0})]


def build(kinds, ids, per_rule, policy='fixed', set_all=None):
    rs = make_rule_set({'kinds': kinds, 'ids': ids, 'policy': policy, 'set': set_all or {}})
    for r in rs.rules:
        for k, v in per_rule.get(r.id, {}).items():
            setattr(r, k, v)
    return rs


def strict(truth, dets, res):
    """scoring_check.py's rule for every segment: attacker alert-seconds in an in-scope window without attacker -> victim
    traffic count as false alarms of the segment the window starts in."""
    ign = {seg: 0 for seg, _ in truth.segments}
    for name, s, e, in_scope in truth.windows:
        if not in_scope:
            continue
        att = {int(t) for t, src, _sc, _r in dets if (w := truth.window_of(src, t)) and w[0] == name}
        ign[truth.segment(s)] += len(att - truth.active[name])
    out = {}
    for seg, m in res['segments'].items():
        tp, fp = m['tp'], m['fp_secs']
        p = tp / (tp + fp + ign[seg]) if tp + fp + ign[seg] else 0.0
        r = m['recall']
        out[seg] = {'ignored': ign[seg], 'precision': p, 'f1': 2 * p * r / (p + r) if p + r else 0.0}
    return out


_TRUTH = {}


def run_one(args):
    day_name, (label, kinds, ids, per_rule, policy, set_all) = args
    path = DAYS[day_name].capture()
    if day_name not in _TRUTH:
        _TRUTH[day_name] = Truth(DAYS[day_name], path)
    truth = _TRUTH[day_name]
    rs = build(kinds, ids, per_rule, policy, set_all)
    dets = []
    eng = RuleEngine(rs, on_detection=lambda d: dets.append((d.time, d.src, d.score, d.rule_ids)))
    t0 = time.time()
    for rec in pr.iter_any(path):
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    eng.flush()
    res = score(truth, dets, 1)
    # time to detect as in derived_tables.py / Table IV: first alert on the attacker in a second with attack traffic
    first = {}
    for t, src, _sc, _r in dets:
        w = truth.window_of(src, t)
        if w is not None and w[1] and int(t) in truth.active[w[0]]:
            first[w[0]] = min(first.get(w[0], t), t)
    starts = {name: s for name, s, e, in_scope in truth.windows}
    res['ttd_true'] = {name: first[name] - starts[name] if name in first else None for name in res['windows']}
    res.update({'label': label, 'day': day_name, 'seconds': time.time() - t0, 'packets': eng.packets,
                'rules': [{'id': r.id, 'measure': r.measure, 'value': r.value, 'op': r.op,
                           'window_seconds': r.window_seconds if r.measure != 'rejected_probes'
                           else (r.window_seconds or r.params.get('window_seconds', 60.0))} for r in rs.rules],
                'strict': strict(truth, dets, res)})
    return res


def run_all(jobs):
    t0 = time.time()
    out = []
    with Pool(min(8, os.cpu_count() or 1)) as pool:
        for i, r in enumerate(pool.imap_unordered(run_one, jobs), 1):
            out.append(r)
            print(f'  [{i}/{len(jobs)}] {r["day"]:<9} {r["label"]:<28} ' + '  '.join(
                f"{s} F1 {pct(m['f1'])}/{pct(r['strict'][s]['f1'])}" for s, m in r['segments'].items()) +
                f'  ({r["seconds"]:.0f}s run, {time.time() - t0:.0f}s total)', flush=True)
    return out, time.time() - t0


def same(a, b):
    return a['segments'] == b['segments'] and a['windows'] == b['windows']


def reproduce():
    jobs = [(d, c) for d in DAY_NAMES for c in TABLE3]
    out, wall = run_all(jobs)
    L = ['# R2: default configurations reproduce Table III', '',
         'Reproduce: `python -m experiments.window_matching reproduce`. Each row re-runs a Table III configuration',
         'with the engine after the window change and compares the full score() output (per-segment TP, FP seconds, P, R,',
         'F1, FP/h and per-window recall and TTD, as unrounded floats) with `results/<day>/results.json`.', '',
         '| Day | Configuration | DEV/all F1 | TEST F1 | identical to results.json |', '|---|---|---|---|---|']
    ok = True
    for r in sorted(out, key=lambda r: (r['day'], [c[0] for c in TABLE3].index(r['label']))):
        old = {x['label']: x for x in json.load(open(os.path.join(ROOT, 'results', r['day'], 'results.json')))['results']}
        eq = same(r, old[r['label']])
        ok &= eq
        segs = list(r['segments'])
        L.append(f"| {r['day']} | {r['label']} | {pct(r['segments'][segs[0]]['f1'])} | "
                 f"{pct(r['segments']['test']['f1']) if 'test' in segs else '–'} | {'yes' if eq else '**NO**'} |")
    L += ['', f'All identical: **{"yes" if ok else "NO"}**. Wall time {wall:.0f} s (8 processes).']
    d = os.path.join(OUT, 'r2_reproduction')
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'results.md'), 'w').write('\n'.join(L) + '\n')
    print('\n'.join(L))
    return ok


def to_markdown(results, wall):
    by = {(r['day'], r['label']): r for r in results}
    labels = [c[0] for c in CONFIGS]

    def ttd(r, w):
        v = r['ttd_true'][w]
        return '–' if v is None else f'{v:,.1f}'

    def thr(r):
        return '; '.join(f"{x['id']} {x['op']} {x['value']:g}" + (f" @{x['window_seconds']:g}s" if x['window_seconds'] else '')
                         for x in r['rules'] if x['measure'] not in ('half_open_ratio', 'port_entropy'))

    L = ['# Window-matching experiment (revision 2, pre-registered)', '',
         'Pre-registration: `docs/preregistration/window_matching.md` (commit 6525bee, before any code change or run).',
         'Reproduce: `python -m experiments.window_matching`. All runs use fixed thresholds.', '',
         'Default = the paper\'s per-second scoring (`experiments.score`). Strict = attacker alert-seconds inside an attack',
         'window in which the attacker sent nothing to the victim count as false alarms (`scoring_check.py`, here applied to',
         'every segment). F1 uses the same recall under both rules. TTD = first true alert (an alert on the attacker in a',
         'second with attacker -> victim traffic), s after the window start, as in Table IV (`derived_tables.py`).', '',
         '## 1. Friday',
         '', '| Configuration | DEV P | DEV R | DEV F1 | DEV strict P | DEV strict F1 | scan TTD | TEST P | TEST R | TEST F1 | '
         'TEST strict P | TEST strict F1 | DDoS TTD | DEV FP/h | TEST FP/h |', '|' + '---|' * 15]
    for lab in labels:
        r = by[('friday', lab)]
        d, t, sd, st = r['segments']['dev'], r['segments']['test'], r['strict']['dev'], r['strict']['test']
        L.append(f"| {lab} | {pct(d['precision'])} | {pct(d['recall'])} | {pct(d['f1'])} | {pct(sd['precision'])} | "
                 f"{pct(sd['f1'])} | {ttd(r, 'PortScan')} | {pct(t['precision'])} | {pct(t['recall'])} | {pct(t['f1'])} | "
                 f"{pct(st['precision'])} | {pct(st['f1'])} | {ttd(r, 'DDoS')} | {d['fp_per_hour']:.1f} | {t['fp_per_hour']:.1f} |")
    wins = [w for w in by[('wednesday', labels[0])]['windows']]
    L += ['', '## 2. Wednesday (held out)', '',
          '| Configuration | P | R | F1 | FP/h | FP s | strict P | strict F1 | ' + ' | '.join(f'recall {w}' for w in wins) + ' |',
          '|' + '---|' * (8 + len(wins))]
    for lab in labels:
        r = by[('wednesday', lab)]
        m, s = r['segments']['all'], r['strict']['all']
        L.append(f"| {lab} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['f1'])} | {m['fp_per_hour']:.1f} | "
                 f"{m['fp_secs']} | {pct(s['precision'])} | {pct(s['f1'])} | " +
                 ' | '.join(pct(r['windows'][w]['recall']) for w in wins) + ' |')
    L += ['', '## 3. Counts behind the strict rule', '',
          '| Day | Configuration | segment | TP s | FP s | ignored attacker s |', '|---|---|---|---|---|---|']
    for day in DAY_NAMES:
        for lab in labels:
            r = by[(day, lab)]
            for seg, m in r['segments'].items():
                L.append(f"| {day} | {lab} | {seg} | {m['tp']} | {m['fp_secs']} | {r['strict'][seg]['ignored']} |")
    L += ['', '## 4. Reproduction checks (pre-registration section 3)', '',
          '| Configuration | existing label | Friday identical | Wednesday identical |', '|---|---|---|---|']
    for lab, old in REPRODUCES.items():
        cells = []
        for day in DAY_NAMES:
            prev = {x['label']: x for x in json.load(open(os.path.join(ROOT, 'results', day, 'results.json')))['results']}
            cells.append('yes' if same(by[(day, lab)], prev[old]) else '**NO**')
        L.append(f'| {lab} | {old} | ' + ' | '.join(cells) + ' |')
    L += ['', '## 5. Thresholds actually run (count rules and rejected_probes; half_open and port_entropy unchanged)', '',
          '| Configuration | thresholds |', '|---|---|']
    L += [f"| {lab} | {thr(by[('friday', lab)])} |" for lab in labels]
    L += ['', '## 6. Run times', '', '| Configuration | Friday s | Wednesday s | packets Friday | packets Wednesday |',
          '|---|---|---|---|---|']
    L += [f"| {lab} | {by[('friday', lab)]['seconds']:.0f} | {by[('wednesday', lab)]['seconds']:.0f} | "
          f"{by[('friday', lab)]['packets']:,} | {by[('wednesday', lab)]['packets']:,} |" for lab in labels]
    L += ['', f'Wall time for all {len(results)} runs: {wall:.0f} s on 8 processes.']
    return '\n'.join(L) + '\n'


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'reproduce':
        sys.exit(0 if reproduce() else 1)
    jobs = [(d, (lab, kinds, ids, per, 'fixed', {})) for d in DAY_NAMES for lab, kinds, ids, per in CONFIGS]
    print(f'window matching: {len(jobs)} runs', flush=True)
    out, wall = run_all(jobs)
    os.makedirs(OUT, exist_ok=True)
    json.dump({'preregistration': 'docs/preregistration/window_matching.md', 'wall_seconds': wall, 'results': out},
              open(os.path.join(OUT, 'results.json'), 'w'), indent=1)
    md = to_markdown(out, wall)
    open(os.path.join(OUT, 'results.md'), 'w').write(md)
    print(md)


if __name__ == '__main__':
    main()
