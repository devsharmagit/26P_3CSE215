"""
Revision 3: per-second outcomes for the bootstrap confidence intervals (pre-registered in
docs/preregistration/confidence_intervals.md).

Re-runs the Table III and window-matching configurations with the unchanged engine and stores, for every integer second of
each scored segment, whether it is a positive (pos), a covered positive (tp), a false-alarm second (fp) or an attacker
alert-second without attack traffic (ign, counted as a false alarm by the strict rule). The totals must equal the stored
results exactly (reproduction check), otherwise the script exits with an error.

    python -m experiments.ci_per_second     # writes results/confidence_intervals/per_second/<day>.json
"""
import json
import math
import os
import sys
from collections import defaultdict
from multiprocessing import Pool

from nids import pcapng_reader as pr
from nids.days import DAYS
from nids.engine import RuleEngine
from experiments.grid import Truth, score
from experiments.window_matching import CONFIGS, TABLE3, build, strict

from nids.paths import ROOT  # noqa: E402  (repository root)
OUT = os.path.join(ROOT, 'results', 'confidence_intervals', 'per_second')
WINDOW_LABELS = ('behaviour @1s (s)', 'count @60s (p)', 'count @60s (u)')
# window-matching configurations that are the same rule set as a Table III configuration
SAME_AS = {'count @1s': 'count / fixed', 'behaviour @60s': 'behaviour / fixed'}
JOBS = [(lab, kinds, ids, per, pol, set_all) for lab, kinds, ids, per, pol, set_all in TABLE3] + \
       [(lab, kinds, ids, per, 'fixed', {}) for lab, kinds, ids, per in CONFIGS if lab in WINDOW_LABELS]

_TRUTH = {}


def truth_for(day):
    if day not in _TRUTH:
        _TRUTH[day] = Truth(DAYS[day], DAYS[day].capture())
    return _TRUTH[day]


def grid(truth):
    """segment -> (first second, last second) of its per-second grid."""
    segs = truth.segments
    out = {}
    for i, (name, st) in enumerate(segs):
        end = segs[i + 1][1] if i + 1 < len(segs) else truth.last
        out[name] = (math.floor(st), math.floor(end))
    return out


def outcomes(truth, dets):
    """segment -> {'tp', 'fp', 'ign'}: sorted lists of seconds (the same rules as experiments.score / window_matching.strict)."""
    tp_units, fp, ign = defaultdict(set), defaultdict(set), defaultdict(set)
    for t, src, _sc, _r in dets:
        w = truth.window_of(src, t)
        if w is None:
            fp[truth.segment(t)].add(int(t))
        elif w[1]:
            tp_units[w[0]].add(int(t))
    tp = defaultdict(set)
    for name, s, e, in_scope in truth.windows:
        if not in_scope:
            continue
        act = truth.active[name]
        for sec in tp_units[name] & act:
            tp[truth.segment(sec)].add(sec)
        ign[truth.segment(s)].update(tp_units[name] - act)
    return {seg: {'tp': sorted(tp[seg]), 'fp': sorted(fp[seg]), 'ign': sorted(ign[seg])} for seg, _ in truth.segments}


def run_one(args):
    day, (label, kinds, ids, per, policy, set_all) = args
    truth = truth_for(day)
    dets = []
    eng = RuleEngine(build(kinds, ids, per, policy, set_all),
                     on_detection=lambda d: dets.append((d.time, d.src, d.score, d.rule_ids)))
    for rec in pr.iter_any(DAYS[day].capture()):
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    eng.flush()
    res = score(truth, dets, 1)
    return day, label, outcomes(truth, dets), res['segments'], strict(truth, dets, res)


def main():
    os.makedirs(OUT, exist_ok=True)
    with Pool(min(8, os.cpu_count() or 1)) as pool:
        runs = pool.map(run_one, [(d, j) for d in ('friday', 'wednesday') for j in JOBS])
    problems = []
    for day in ('friday', 'wednesday'):
        truth = truth_for(day)
        g = grid(truth)
        pos = defaultdict(set)
        for name, s, e, in_scope in truth.windows:
            if in_scope:
                for sec in truth.active[name]:
                    pos[truth.segment(sec)].add(sec)
        stored = {r['label']: r for r in json.load(open(os.path.join(ROOT, 'results', day, 'results.json')))['results']}
        wm = {r['label']: r for r in json.load(open(os.path.join(ROOT, 'results', 'window_matching', 'results.json')))['results']
              if r['day'] == day}
        doc = {'day': day, 'segments': {seg: {'first': a, 'last': b, 'pos': sorted(pos[seg])} for seg, (a, b) in g.items()},
               'configs': {}}
        for d, label, out, segs, st in runs:
            if d != day:
                continue
            doc['configs'][label] = out
            ref = stored.get(label) or wm[label]
            for seg, m in ref['segments'].items():
                a, b = g[seg]
                every = set(pos[seg]) | set(out[seg]['tp']) | set(out[seg]['fp']) | set(out[seg]['ign'])
                if any(not a <= x <= b for x in every):
                    problems.append(f'{day} {label} {seg}: a second outside the segment grid')
                got = (len(pos[seg]), len(out[seg]['tp']), len(out[seg]['fp']))
                exp = (m['positives'], m['tp'], m['fp_secs'])
                if got != exp:
                    problems.append(f'{day} {label} {seg}: pos/tp/fp {got} != stored {exp}')
                if len(out[seg]['ign']) != st[seg]['ignored']:
                    problems.append(f'{day} {label} {seg}: ign {len(out[seg]["ign"])} != strict() {st[seg]["ignored"]}')
            for wlab, tlab in SAME_AS.items():   # the window-matching store also holds ignored counts
                if tlab == label:
                    for seg in out:
                        if len(out[seg]['ign']) != wm[wlab]['strict'][seg]['ignored']:
                            problems.append(f'{day} {label} {seg}: ign != window_matching {wlab}')
            if label in wm:
                for seg in out:
                    if len(out[seg]['ign']) != wm[label]['strict'][seg]['ignored']:
                        problems.append(f'{day} {label} {seg}: ign != window_matching')
        json.dump(doc, open(os.path.join(OUT, f'{day}.json'), 'w'))
        print(f'{day}: {len(doc["configs"])} configurations, segments ' +
              ', '.join(f'{s} {b - a + 1:,} s' for s, (a, b) in g.items()))
    if problems:
        print('REPRODUCTION CHECK FAILED:\n  ' + '\n  '.join(problems))
        sys.exit(1)
    print('reproduction check: per-second totals equal the stored results for every configuration and segment')


if __name__ == '__main__':
    main()
