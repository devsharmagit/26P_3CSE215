"""
T04: best fixed vs best adaptive setting per rule family, and threshold sensitivity (Friday only).

The design is fixed in docs/preregistration/sensitivity_sweep.md (written before any run):
    fixed     one strictness scale s for every rule in the family
    adaptive  floor scale f (same mapping as s) x multiplier level 1-5
Selection: best per family and policy by DEV F1, reported on TEST; plus the oracle maximum per segment.

    python -m experiments.sensitivity          # 66 runs, ~5 min on 8 processes
Writes results/sensitivity/results.json, results.md and fig_sensitivity.png.
"""
import json
import os
import sys
import time
from multiprocessing import Pool

from nids import pcapng_reader as pr
from nids.days import DAYS
from nids.engine import RuleEngine
from experiments.grid import FAMILIES, RULES, Truth, pct, score
from nids.rule_set import load_rules

from nids.paths import ROOT  # noqa: E402  (repository root)
OUT = os.path.join(ROOT, 'results', 'sensitivity')
DAY = 'friday'
SCALES = (0.25, 0.5, 0.75, 1, 1.5, 2, 3)
FLOORS = (0.25, 0.5, 1)
MULT_COUNT = (1.5, 2, 3, 4, 6)
MULT_RATIO = (1.05, 1.1, 1.25, 1.5, 2)
RATIO_RULES = {'half_open', 'port_entropy'}


def scaled_value(rule_id, default, s):
    if rule_id == 'half_open':
        return min(0.99, max(0.5, 1 - 0.2 / s))
    return default * s


def build_jobs():
    jobs = []
    for fam in FAMILIES:
        for s in SCALES:
            jobs.append({'family': fam, 'policy': 'fixed', 'scale': s, 'label': f'{fam} / fixed s={s:g}'})
        for f in FLOORS:
            for lvl in range(5):
                jobs.append({'family': fam, 'policy': 'adaptive', 'floor': f, 'level': lvl + 1,
                             'label': f'{fam} / adaptive floor={f:g} m-level={lvl + 1}'})
    return jobs


def make_rule_set(job):
    rs = load_rules(RULES).variant(policy=job['policy'], kinds=FAMILIES[job['family']])
    for r in rs.rules:
        if job['policy'] == 'fixed':
            r.value = scaled_value(r.id, r.value, job['scale'])
        else:
            r.value = scaled_value(r.id, r.value, job['floor'])
            r.multiplier = (MULT_RATIO if r.id in RATIO_RULES else MULT_COUNT)[job['level'] - 1]
    return rs


_TRUTH = {}


def run(job):
    path = DAYS[DAY].capture()
    if path not in _TRUTH:
        _TRUTH[path] = Truth(DAYS[DAY], path)
    truth = _TRUTH[path]
    rs = make_rule_set(job)
    dets = []
    eng = RuleEngine(rs, on_detection=lambda d: dets.append((d.time, d.src, d.score, d.rule_ids)))
    for rec in pr.iter_any(path):
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    eng.flush()
    res = dict(job)
    res['thresholds'] = {r.id: {'value': round(r.value, 4), 'multiplier': r.multiplier if r.policy == 'adaptive' else None}
                         for r in rs.rules}
    res.update(score(truth, dets, 1))
    return res


def fmt_setting(r):
    return f"s={r['scale']:g}" if r['policy'] == 'fixed' else f"floor={r['floor']:g}, m-level={r['level']}"


def to_markdown(results):
    segs = ('dev', 'test')
    L = ['# T04: best fixed vs best adaptive, and threshold sensitivity (Friday)', '',
         'Design: docs/preregistration/sensitivity_sweep.md (fixed before the run).',
         'Fixed: strictness scale s on every rule of the family. Adaptive: floor scale f x multiplier level',
         f'(counts and rejected_probes m = {MULT_COUNT}; half_open and port_entropy m = {MULT_RATIO}); alpha 0.2, freeze 60 s.',
         'DEV = 08:59-15:40 (PortScan), TEST = 15:40-17:03 (DDoS). Reproduce: `python -m experiments.sensitivity`.', '']
    L += ['## 1. Best by DEV F1, reported on TEST (held-out protocol)', '',
          '| Family | Policy | Setting chosen on DEV | DEV F1 | TEST F1 | DEV FP/h | TEST FP/h |', '|---|---|---|---|---|---|---|']
    for fam in FAMILIES:
        for pol in ('fixed', 'adaptive'):
            rows = [r for r in results if r['family'] == fam and r['policy'] == pol]
            b = max(rows, key=lambda r: r['segments']['dev']['f1'])  # DEV only (first maximum on ties); TEST is never used to choose
            L.append(f"| {fam} | {pol} | {fmt_setting(b)} | {pct(b['segments']['dev']['f1'])} | {pct(b['segments']['test']['f1'])} | "
                     f"{b['segments']['dev']['fp_per_hour']:.1f} | {b['segments']['test']['fp_per_hour']:.1f} |")
    L += ['', '## 2. Oracle: best F1 of each policy on each segment (any setting in the grid)', '',
          '| Family | Segment | best fixed F1 (setting) | best adaptive F1 (setting) | adaptive - fixed |', '|---|---|---|---|---|']
    flags = []
    for fam in FAMILIES:
        for seg in segs:
            best = {}
            for pol in ('fixed', 'adaptive'):
                rows = [r for r in results if r['family'] == fam and r['policy'] == pol]
                best[pol] = max(rows, key=lambda r: r['segments'][seg]['f1'])
            d = best['adaptive']['segments'][seg]['f1'] - best['fixed']['segments'][seg]['f1']
            if d > 0:
                flags.append((fam, seg, d))
            L.append(f"| {fam} | {seg.upper()} | {pct(best['fixed']['segments'][seg]['f1'])} ({fmt_setting(best['fixed'])}) | "
                     f"{pct(best['adaptive']['segments'][seg]['f1'])} ({fmt_setting(best['adaptive'])}) | {d * 100:+.1f} |")
    L += ['', '**Does any adaptive setting beat the best fixed setting?** ' +
          ('YES: ' + '; '.join(f'{f} {s.upper()} by {d * 100:+.1f} F1' for f, s, d in flags) if flags else
           'No: on every family and segment the best adaptive F1 is at most the best fixed F1.'), '']
    L += ['## 3. Every setting', '',
          '| Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | recall PortScan | recall DDoS |',
          '|---|---|---|---|---|---|---|---|---|---|---|']
    for r in results:
        c = [r['label']]
        for s in segs:
            m = r['segments'][s]
            c += [pct(m['precision']), pct(m['recall']), pct(m['f1']), f"{m['fp_per_hour']:.1f}"]
        c += [pct(r['windows'][w]['recall']) for w in ('PortScan', 'DDoS')]
        L.append('| ' + ' | '.join(c) + ' |')
    L += ['', '## 4. Thresholds used per setting', '', 'See results.json (`thresholds` per run).']
    return '\n'.join(L) + '\n', flags


def figure(results, out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size': 8, 'font.family': 'serif'})
    fams = ('count', 'behaviour')
    fig, axes = plt.subplots(2, 3, figsize=(7.0, 4.4), sharey=True)
    seg_style = {'dev': ('k', '-', 'o'), 'test': ('0.45', '--', 's')}
    floor_style = {0.25: ('0.6', ':', '^'), 0.5: ('0.35', '--', 's'), 1: ('k', '-', 'o')}
    for i, fam in enumerate(fams):
        ax = axes[i][0]
        rows = sorted([r for r in results if r['family'] == fam and r['policy'] == 'fixed'], key=lambda r: r['scale'])
        for seg, (c, ls, mk) in seg_style.items():
            ax.plot([r['scale'] for r in rows], [r['segments'][seg]['f1'] * 100 for r in rows], color=c, ls=ls, marker=mk,
                    ms=3.5, label=seg.upper())
        ax.set_xscale('log', base=2)
        ax.set_xticks(SCALES)
        ax.set_xticklabels([f'{s:g}' for s in SCALES])
        ax.set_title(f'{fam} rules, fixed', fontsize=8.5)
        ax.set_ylabel('F1 (%)')
        ax.legend(frameon=False, fontsize=7)
        for j, seg in enumerate(('dev', 'test')):
            ax = axes[i][j + 1]
            for f, (c, ls, mk) in floor_style.items():
                rows = sorted([r for r in results if r['family'] == fam and r['policy'] == 'adaptive' and r['floor'] == f],
                              key=lambda r: r['level'])
                ax.plot([r['level'] for r in rows], [r['segments'][seg]['f1'] * 100 for r in rows], color=c, ls=ls,
                        marker=mk, ms=3.5, label=f'floor x{f:g}')
            best_fixed = max(r['segments'][seg]['f1'] for r in results if r['family'] == fam and r['policy'] == 'fixed') * 100
            ax.axhline(best_fixed, color='0.2', lw=0.8, ls='-.', label='best fixed')
            ax.set_xticks(range(1, 6))
            ax.set_title(f'{fam} rules, adaptive, {seg.upper()}', fontsize=8.5)
            if i == 0 and j == 0:
                ax.legend(frameon=False, fontsize=6.5)
    for j in range(3):
        axes[1][j].set_xlabel('strictness scale s' if j == 0 else 'multiplier level (1 = lowest)')
    for ax in axes.flat:
        ax.set_ylim(-3, 103)
        ax.grid(color='0.88', lw=0.5)
    fig.tight_layout()
    fig.savefig(out, dpi=300)
    plt.close(fig)


def main():
    jobs = build_jobs()
    print(f'{len(jobs)} runs on {DAY}', flush=True)
    t0 = time.time()
    with Pool(min(8, os.cpu_count() or 1)) as pool:
        results = []
        for i, r in enumerate(pool.imap_unordered(run, jobs), 1):
            results.append(r)
            print(f"  [{i}/{len(jobs)}] {r['label']:<44} DEV F1 {pct(r['segments']['dev']['f1'])}  "
                  f"TEST F1 {pct(r['segments']['test']['f1'])}  ({time.time() - t0:.0f}s)", flush=True)
    order = {j['label']: i for i, j in enumerate(jobs)}
    results.sort(key=lambda r: order[r['label']])
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'results.json'), 'w') as f:
        json.dump({'day': DAY, 'scales': SCALES, 'floors': FLOORS, 'mult_count': MULT_COUNT, 'mult_ratio': MULT_RATIO,
                   'results': results}, f, indent=1)
    md, flags = to_markdown(results)
    with open(os.path.join(OUT, 'results.md'), 'w') as f:
        f.write(md)
    figure(results, os.path.join(OUT, 'fig_sensitivity.png'))
    print(f'wrote {OUT} ({time.time() - t0:.0f}s); adaptive beats best fixed: {flags or "no"}')


if __name__ == '__main__':
    sys.exit(main())
