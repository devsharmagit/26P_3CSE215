"""
Revision 3: moving-block bootstrap confidence intervals (pre-registered in
docs/preregistration/confidence_intervals.md). Reads the per-second outcomes written by ci_per_second.py; does not
run the engine.

    python -m experiments.bootstrap_ci      # writes results/confidence_intervals/results.md and results.json

F1 from per-second sums: default 2TP/(POS+TP+FP), strict 2TP/(POS+TP+FP+IGN) (= 2PR/(P+R) with the paper's P and R).
Block starts are drawn once per (segment, block length) and shared by every configuration, so differences are paired.
"""
import json
import os

import numpy as np

from nids.paths import ROOT  # noqa: E402  (repository root)
BASE = os.path.join(ROOT, 'results', 'confidence_intervals')
SEED = 20261026
B = 2000
BLOCKS = (60, 30, 300)          # primary first
PRIMARY = 60
FAMILIES = ('count', 'behaviour', 'all')


# ------------------------------------------------------------------------------------------------ core (tested)
def block_starts(rng, n, block, b):
    """(b, k) start indices of a moving-block bootstrap of n seconds with blocks of `block` seconds."""
    k = -(-n // block)
    return rng.integers(0, n - block + 1, size=(b, k))


def resampled_sums(x, starts, block):
    """Sum of x over each resample: k blocks of `block` seconds, concatenated and truncated to len(x)."""
    n = len(x)
    c = np.concatenate(([0], np.cumsum(x, dtype=np.int64)))
    k = starts.shape[1]
    lengths = np.full(k, block)
    lengths[-1] = n - (k - 1) * block
    return (c[starts + lengths] - c[starts]).sum(axis=1)


def f1(tp, pos, fp, ign=0):
    """F1 in percent from totals (arrays or scalars); 0 where the denominator is 0."""
    tp, den = np.asarray(tp, float), np.asarray(pos + tp + fp + ign, float)
    return np.where(den > 0, 200.0 * tp / np.where(den > 0, den, 1), 0.0)


def interval(values):
    lo, hi = np.percentile(values, [2.5, 97.5])
    return float(lo), float(hi)


# ------------------------------------------------------------------------------------------------ data
def load(day):
    doc = json.load(open(os.path.join(BASE, 'per_second', f'{day}.json')))
    segs = {}
    for seg, g in doc['segments'].items():
        n = g['last'] - g['first'] + 1

        def arr(secs, first=g['first'], n=n):
            a = np.zeros(n, dtype=np.int8)
            a[np.asarray(secs, dtype=np.int64) - first] = 1
            return a
        segs[seg] = {'n': n, 'pos': arr(g['pos']),
                     'cfg': {lab: {k: arr(out[seg][k]) for k in ('tp', 'fp', 'ign')} for lab, out in doc['configs'].items()}}
    return segs


# ------------------------------------------------------------------------------------------------ analysis
LEVEL_ORDER = ['count / fixed', 'count / adaptive', 'behaviour / fixed', 'behaviour / adaptive', 'all / fixed',
               'all / adaptive', 'all / adaptive, no freeze', 'behaviour @1s (s)', 'count @60s (p)', 'count @60s (u)']
ALIAS = {'count / fixed': 'count / fixed (= count @1s)', 'behaviour / fixed': 'behaviour / fixed (= behaviour @60s)'}
SEG_NAME = {('friday', 'dev'): 'Fri DEV', ('friday', 'test'): 'Fri TEST', ('wednesday', 'all'): 'Wed'}


def differences(seg_key):
    """(group, label, A, B): A − B."""
    out = []
    if seg_key == ('friday', 'dev'):
        out += [('a', 'measure, unmatched: behaviour/fixed − count/fixed', 'behaviour / fixed', 'count / fixed'),
                ('a', 'measure, matched 1 s: behaviour @1s (s) − count @1s', 'behaviour @1s (s)', 'count / fixed'),
                ('a', 'measure, matched 60 s: behaviour @60s − count @60s (p)', 'behaviour / fixed', 'count @60s (p)'),
                ('a', 'measure, matched 60 s: behaviour @60s − count @60s (u)', 'behaviour / fixed', 'count @60s (u)')]
    else:
        out += [('a', 'measure, unmatched: behaviour/fixed − count/fixed', 'behaviour / fixed', 'count / fixed')]
    out += [('b', f'policy: {f}/fixed − {f}/adaptive', f'{f} / fixed', f'{f} / adaptive') for f in FAMILIES]
    out += [('c', 'freeze: all/adaptive − all/adaptive no freeze', 'all / adaptive', 'all / adaptive, no freeze')]
    return out


def analyse():
    rng = np.random.default_rng(SEED)
    res = {'seed': SEED, 'B': B, 'blocks': list(BLOCKS), 'primary_block': PRIMARY, 'segments': {}}
    for day in ('friday', 'wednesday'):
        for seg, d in load(day).items():
            key = SEG_NAME[(day, seg)]
            n = d['n']
            point = {}
            for lab, a in d['cfg'].items():
                tp, fp, ign, pos = a['tp'].sum(), a['fp'].sum(), a['ign'].sum(), d['pos'].sum()
                point[lab] = {'default': float(f1(tp, pos, fp)), 'strict': float(f1(tp, pos, fp, ign))}
            reps = {}
            for block in BLOCKS:            # draws in this fixed order: friday dev, test, wednesday; 60, 30, 300
                st = block_starts(rng, n, block, B)
                pos = resampled_sums(d['pos'], st, block)
                reps[block] = {}
                for lab, a in d['cfg'].items():
                    tp, fp, ign = (resampled_sums(a[k], st, block) for k in ('tp', 'fp', 'ign'))
                    reps[block][lab] = {'default': f1(tp, pos, fp), 'strict': f1(tp, pos, fp, ign)}
            levels = {lab: {sc: {'point': point[lab][sc], **{f'ci{bl}': interval(reps[bl][lab][sc]) for bl in BLOCKS}}
                            for sc in ('default', 'strict')} for lab in d['cfg']}
            diffs = []
            for grp, label, a, b in differences((day, seg)):
                row = {'group': grp, 'label': label}
                for sc in ('default', 'strict'):
                    row[sc] = {'point': point[a][sc] - point[b][sc],
                               'printed': round(float(fmt(point[a][sc])) - float(fmt(point[b][sc])), 1),
                               **{f'ci{bl}': interval(reps[bl][a][sc] - reps[bl][b][sc]) for bl in BLOCKS}}
                diffs.append(row)
            # (d) |measure effect| − max |policy effect|, inside each resample
            row = {'group': 'd', 'label': '|measure| − max |policy| (title claim)'}
            for sc in ('default', 'strict'):
                def dstat(v):
                    m = abs(v['behaviour / fixed'][sc] - v['count / fixed'][sc])
                    p = np.max([abs(v[f'{f} / fixed'][sc] - v[f'{f} / adaptive'][sc]) for f in FAMILIES], axis=0)
                    return m - p
                row[sc] = {'point': float(dstat(point)), **{f'ci{bl}': interval(dstat(reps[bl])) for bl in BLOCKS}}
            diffs.append(row)
            res['segments'][key] = {'seconds': n, 'levels': levels, 'differences': diffs}
    return res


# ------------------------------------------------------------------------------------------------ report
def fmt(v):
    return f'{v:.1f}'


def cell(x, bl=PRIMARY):
    lo, hi = x[f'ci{bl}']
    return f'{fmt(x["point"])} [{fmt(lo)}, {fmt(hi)}]'


def supported(x, bl=PRIMARY):
    lo, hi = x[f'ci{bl}']
    return lo > 0 or hi < 0


def to_markdown(res):
    L = ['# Bootstrap confidence intervals (revision 3, pre-registered)', '',
         'Pre-registration: `docs/preregistration/confidence_intervals.md` (commit 3d3d237, before any computation).',
         'Reproduce: `python -m experiments.ci_per_second && python -m experiments.bootstrap_ci`.', '',
         f'Moving-block bootstrap over seconds within each segment; B = {res["B"]}; seed {res["seed"]} '
         '(`numpy.random.default_rng`); blocks drawn once per (segment, block length) and shared by all configurations '
         '(paired). 95% percentile intervals. Primary block length 60 s; 30 s and 300 s as sensitivity. F1 in %, point = '
         'full-sample value (equal to the published one). "Supported" = the 60 s interval excludes zero.', '',
         'Scope: per-second sampling variability within these captures; not variability across attacks, attackers or '
         'datasets.', '',
         '"paper (printed values)" = difference of the one-decimal values printed in the results files, as quoted in the paper; '
         'the bootstrap point uses unrounded F1 and can differ from it by 0.1.', '']
    for key, s in res['segments'].items():
        L += [f'## {key} ({s["seconds"]:,} s)', '', '### F1 levels, 95% CI (block 60 s)', '',
              '| Configuration | default | strict |', '|---|---|---|']
        for lab in LEVEL_ORDER:
            if lab in s['levels']:
                v = s['levels'][lab]
                L.append(f'| {ALIAS.get(lab, lab)} | {cell(v["default"])} | {cell(v["strict"])} |')
        L += ['', '### Paired differences (A − B)', '',
              '| group | difference | scoring | paper (printed values) | point [95% CI], 60 s | supported | 30 s | 300 s |',
              '|---|---|---|---|---|---|---|---|']
        for d in s['differences']:
            for sc in ('default', 'strict'):
                x = d[sc]
                L.append(f'| ({d["group"]}) | {d["label"]} | {sc} | {fmt(x["printed"]) if "printed" in x else "–"} | {cell(x)} | {"yes" if supported(x) else "**no**"} | '
                         f'[{fmt(x["ci30"][0])}, {fmt(x["ci30"][1])}] | [{fmt(x["ci300"][0])}, {fmt(x["ci300"][1])}] |')
        L.append('')
    flags = [(k, d['label'], sc) for k, s in res['segments'].items() for d in s['differences']
             if d['group'] in 'abc' for sc in ('default', 'strict') if not supported(d[sc])]
    L += ['## STOP-FLAG check (pre-registration §4)', '',
          f'Intervals for (a), (b) or (c) that include zero at 60 s: **{len(flags)}**.', '']
    L += [f'- {k}: {lab} ({sc})' for k, lab, sc in flags]
    return '\n'.join(L) + '\n', flags


def main():
    res = analyse()
    md, flags = to_markdown(res)
    json.dump(res, open(os.path.join(BASE, 'results.json'), 'w'), indent=1)
    open(os.path.join(BASE, 'results.md'), 'w').write(md)
    print(md)


if __name__ == '__main__':
    main()
