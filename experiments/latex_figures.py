"""
Vector-PDF versions of the paper's two figures for the IEEE LaTeX build (final-latex). Reads existing results files only
(results/sensitivity/results.json, results/sensitivity/trace_per_second.csv) and writes nothing under results/.
Same data and layout as paper_figures.py; fonts are larger for print size and embedded as TrueType (no Type 3).

    python -m experiments.latex_figures      # writes results/figures/fig_sensitivity.pdf, fig_trace.pdf
"""
import csv
import datetime
import json
import os
from collections import defaultdict

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

from nids.days import ADT  # noqa: E402

from nids.paths import ROOT  # noqa: E402  (repository root)
OUT = os.path.join(ROOT, 'results', 'figures')
W = 3.45
plt.rcParams.update({'font.size': 8, 'font.family': 'serif', 'axes.linewidth': 0.6, 'pdf.fonttype': 42,
                     'ps.fonttype': 42})
TRACE_START = datetime.datetime(2017, 7, 7, 15, 54, tzinfo=ADT).timestamp()
TRACE_LABELS = ['m=3, freeze (default)', 'm=3, no freeze', 'm=4, freeze']


def fig_sensitivity():
    res = json.load(open(os.path.join(ROOT, 'results', 'sensitivity', 'results.json')))['results']
    fig, axes = plt.subplots(1, 2, figsize=(W, 1.75), sharey=True)
    styles = {0.25: ('0.55', ':', '^'), 0.5: ('0.35', '--', 's'), 1: ('black', '-', 'o')}
    for ax, (fam, seg, title) in zip(axes, (('behaviour', 'dev', 'behaviour, Fri. scan (DEV)'),
                                            ('count', 'test', 'count, Fri. DDoS (TEST)'))):
        for f, (c, ls, mk) in styles.items():
            rows = sorted([r for r in res if r['family'] == fam and r['policy'] == 'adaptive' and r['floor'] == f],
                          key=lambda r: r['level'])
            ax.plot([r['level'] for r in rows], [r['segments'][seg]['f1'] * 100 for r in rows], color=c, ls=ls, marker=mk,
                    ms=3, lw=0.9, label=f'adaptive, floor ×{f:g}')
        best = max(r['segments'][seg]['f1'] for r in res if r['family'] == fam and r['policy'] == 'fixed') * 100
        ax.axhline(best, color='black', lw=1.4, alpha=0.35, label='best fixed (any s)')
        ax.set_title(title, fontsize=7.5)
        ax.set_xticks(range(1, 6))
        ax.set_ylim(-3, 105)
        ax.tick_params(length=2, labelsize=7)
    axes[0].set_ylabel('F1 (%)')
    fig.supxlabel('multiplier level (1 = lowest)', fontsize=7.5, y=0.02)
    axes[0].legend(frameon=False, fontsize=6.5, loc='lower left')
    fig.tight_layout(pad=0.3, w_pad=0.5)
    fig.savefig(os.path.join(OUT, 'fig_sensitivity.pdf'))
    plt.close(fig)


def fig_trace():
    rows, hits = defaultdict(list), defaultdict(list)
    with open(os.path.join(ROOT, 'results', 'sensitivity', 'trace_per_second.csv')) as f:
        for r in csv.DictReader(f):
            t = float(r['time_utc'])
            rows[r['config']].append((t, int(r['victim_pps']), float(r['pps_threshold'])))
            if r['attacker_detected'] == '1':
                hits[r['config']].append(int(t))
    fig, axes = plt.subplots(3, 1, figsize=(W, 3.0), sharex=True)
    t0 = TRACE_START
    for ax, label in zip(axes, TRACE_LABELS):
        xs = [(t - t0) / 60 for t, _, _ in rows[label]]
        ax.axvspan(2, 23.98, color='0.92', zorder=0)
        ax.plot(xs, [p for _, p, _ in rows[label]], color='0.6', lw=0.4, label='packets/s to victim')
        ax.plot(xs, [min(th, 2550) for _, _, th in rows[label]], color='black', lw=0.9, label='threshold max(400, m·baseline)')
        hx = [(h - t0) / 60 for h in hits[label]]
        ax.plot(hx, [-180] * len(hx), '|', color='black', ms=3.5, mew=0.4, label='alert second on attacker')
        ax.set_ylim(-320, 2600)
        ax.set_yticks([0, 1000, 2000])
        ax.set_ylabel('pkt/s', fontsize=7)
        ax.tick_params(length=2, labelsize=7)
        n = len(hits[label])
        ax.set_title(f'{label}: {n} alert second{"" if n == 1 else "s"} on the attacker', fontsize=7, loc='left', pad=2)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, frameon=False, fontsize=6.5, loc='upper center', ncol=2, handlelength=1.5, columnspacing=1.0)
    axes[-1].set_xlabel('minutes after 15:54 ADT (shaded: DDoS window)', fontsize=7)
    fig.tight_layout(pad=0.3, h_pad=0.35, rect=(0, 0, 1, 0.88))
    fig.savefig(os.path.join(OUT, 'fig_trace.pdf'))
    plt.close(fig)
    return {label: len(hits[label]) for label in TRACE_LABELS}


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    fig_sensitivity()
    print('alert seconds per trace panel:', fig_trace())
