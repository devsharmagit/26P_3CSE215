"""
Column-width, greyscale figures for the paper (IEEE two-column, 3.45 in wide), from existing results files only,
plus a per-second trace of the victim-packet-flood threshold during the Friday DDoS (re-runs three existing
configurations unchanged).

    python -m experiments.paper_figures      # ~2 min; writes results/figures/*.png and results/sensitivity/trace_per_second.csv
"""
import csv
import datetime
import json
import os
from multiprocessing import Pool

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

from nids import pcapng_reader as pr  # noqa: E402
from experiments import sensitivity as S  # noqa: E402
from nids.days import ADT, DAYS  # noqa: E402
from nids.engine import RuleEngine  # noqa: E402

from nids.paths import ROOT  # noqa: E402  (repository root)
FIG = os.path.join(ROOT, 'results', 'figures')
W = 3.45
plt.rcParams.update({'font.size': 7, 'font.family': 'serif', 'axes.linewidth': 0.6, 'hatch.linewidth': 0.5})
VICTIM, ATTACKER = '192.168.10.50', '172.16.0.1'


def load(rel):
    return json.load(open(os.path.join(ROOT, 'results', rel)))


def fig_grid():
    fri = {r['label']: r for r in load('friday/results.json')['results']}
    wed = {r['label']: r for r in load('wednesday/results.json')['results']}
    panels = [('Fri. scan (DEV)', fri, 'dev'), ('Fri. DDoS (TEST)', fri, 'test'), ('Wed. DoS (held-out)', wed, 'all')]
    fams = ['count', 'behaviour', 'all']
    fig, axes = plt.subplots(1, 3, figsize=(W, 1.75), sharey=True)
    for ax, (title, data, seg) in zip(axes, panels):
        for j, (pol, face, hatch) in enumerate((('fixed', '0.2', None), ('adaptive', 'white', '////'))):
            xs = [i + (j - 0.5) * 0.38 for i in range(3)]
            vals = [data[f'{f} / {pol}']['segments'][seg]['f1'] * 100 for f in fams]
            ax.bar(xs, vals, width=0.36, color=face, edgecolor='black', linewidth=0.5, hatch=hatch, label=pol)
        ax.set_xticks(range(3))
        ax.set_xticklabels(['count', 'behav.', 'all'], fontsize=6.5)
        ax.set_title(title, fontsize=6.5)
        ax.set_ylim(0, 110)
        ax.tick_params(length=2, labelsize=6)
    axes[0].set_ylabel('F1 (%)')
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, [x + ' thresholds' for x in l], frameon=False, fontsize=6, loc='upper center', ncol=2)
    fig.tight_layout(pad=0.3, w_pad=0.4, rect=(0, 0, 1, 0.9))
    fig.savefig(os.path.join(FIG, 'fig_grid.png'), dpi=300)
    plt.close(fig)


def fig_sensitivity():
    res = load('sensitivity/results.json')['results']
    fig, axes = plt.subplots(1, 2, figsize=(W, 1.6), sharey=True)
    styles = {0.25: ('0.55', ':', '^'), 0.5: ('0.35', '--', 's'), 1: ('black', '-', 'o')}
    for ax, (fam, seg, title) in zip(axes, (('behaviour', 'dev', 'behaviour rules, Fri. scan (DEV)'),
                                            ('count', 'test', 'count rules, Fri. DDoS (TEST)'))):
        for f, (c, ls, mk) in styles.items():
            rows = sorted([r for r in res if r['family'] == fam and r['policy'] == 'adaptive' and r['floor'] == f], key=lambda r: r['level'])
            ax.plot([r['level'] for r in rows], [r['segments'][seg]['f1'] * 100 for r in rows], color=c, ls=ls, marker=mk, ms=2.5, lw=0.8,
                    label=f'adaptive, floor ×{f:g}')
        best = max(r['segments'][seg]['f1'] for r in res if r['family'] == fam and r['policy'] == 'fixed') * 100
        ax.axhline(best, color='black', lw=1.4, alpha=0.35, label='best fixed (any s)')
        ax.set_title(title, fontsize=6.5)
        ax.set_xticks(range(1, 6))
        ax.set_xlabel('multiplier level (1 = lowest)', fontsize=6.5)
        ax.set_ylim(-3, 105)
        ax.tick_params(length=2, labelsize=6)
    axes[0].set_ylabel('F1 (%)')
    axes[0].legend(frameon=False, fontsize=5.2, loc='lower left')
    fig.tight_layout(pad=0.3, w_pad=0.5)
    fig.savefig(os.path.join(FIG, 'fig_sensitivity.png'), dpi=300)
    plt.close(fig)


TRACE_START = datetime.datetime(2017, 7, 7, 15, 54, tzinfo=ADT).timestamp()
TRACE_END = datetime.datetime(2017, 7, 7, 16, 20, tzinfo=ADT).timestamp()
TRACES = [  # (label, sensitivity.py job, freeze_seconds override)
    ('m=3, freeze (default)', {'family': 'count', 'policy': 'adaptive', 'floor': 1, 'level': 3, 'label': 'a'}, None),
    ('m=3, no freeze', {'family': 'count', 'policy': 'adaptive', 'floor': 1, 'level': 3, 'label': 'b'}, 0.0),
    ('m=4, freeze', {'family': 'count', 'policy': 'adaptive', 'floor': 1, 'level': 4, 'label': 'c'}, None),
]


def trace(args):
    label, job, freeze = args
    rs = S.make_rule_set(job)
    for r in rs.rules:
        if freeze is not None:
            r.freeze_seconds = freeze
    rule = next(r for r in rs.rules if r.id == 'victim_packet_flood')
    rows, dets = [], []

    class Traced(RuleEngine):
        def _rollover(self):
            t = self.window_start
            if TRACE_START <= t <= TRACE_END:
                b = self.baseline[rule.id].get(VICTIM) or 0.0
                rows.append((t, self.victim_pkts.get(VICTIM, 0), max(rule.value, rule.multiplier * b)))
            super()._rollover()

    eng = Traced(rs, on_detection=dets.append)
    for rec in pr.iter_any(DAYS['friday'].capture()):
        if rec[0] > TRACE_END + 5:
            break
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    hits = sorted({int(d.time) for d in dets if d.src == ATTACKER and TRACE_START <= d.time <= TRACE_END})
    return label, rows, hits


def fig_trace():
    with Pool(3) as pool:
        out = pool.map(trace, TRACES)
    with open(os.path.join(ROOT, 'results', 'sensitivity', 'trace_per_second.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['config', 'time_utc', 'victim_pps', 'pps_threshold', 'attacker_detected'])
        for label, rows, hits in out:
            hs = set(hits)
            for t, pps, thr in rows:
                w.writerow([label, f'{t:.0f}', pps, f'{thr:.1f}', int(int(t) in hs)])
    fig, axes = plt.subplots(3, 1, figsize=(W, 2.9), sharex=True)
    t0 = TRACE_START
    for ax, (label, rows, hits) in zip(axes, out):
        xs = [(t - t0) / 60 for t, _, _ in rows]
        ax.axvspan(2, 23.98, color='0.92', zorder=0)
        ax.plot(xs, [p for _, p, _ in rows], color='0.6', lw=0.4, label='packets/s to the victim')
        ax.plot(xs, [min(th, 2550) for _, _, th in rows], color='black', lw=0.9, label='threshold max(400, m x baseline)')
        hx = [(h - t0) / 60 for h in hits]
        ax.plot(hx, [-180] * len(hx), '|', color='black', ms=3, mew=0.4, label='second with an alert on the attacker')
        ax.set_ylim(-320, 2600)
        ax.set_yticks([0, 1000, 2000])
        ax.set_ylabel('pkt/s', fontsize=6)
        ax.tick_params(length=2, labelsize=5.5)
        ax.set_title(f'{label}: {len(hits)} alert second{"" if len(hits) == 1 else "s"} on the attacker', fontsize=6, loc='left', pad=2)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, frameon=False, fontsize=5.2, loc='upper center', ncol=2)
    axes[-1].set_xlabel('minutes after 15:54 ADT (shaded: DDoS window 15:56-16:17:59)', fontsize=6)
    fig.tight_layout(pad=0.3, h_pad=0.3, rect=(0, 0, 1, 0.9))
    fig.savefig(os.path.join(FIG, 'fig_trace.png'), dpi=300)
    plt.close(fig)
    return {label: len(hits) for label, _, hits in out}


if __name__ == '__main__':
    os.makedirs(FIG, exist_ok=True)
    fig_grid()
    fig_sensitivity()
    print('trace alert seconds:', fig_trace())
    print('wrote', FIG)
