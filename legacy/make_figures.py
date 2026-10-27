"""
Paper figures from results/<day>/results.json (run experiments.py first).

    python -m legacy.make_figures friday      -> results/friday/fig_family_policy.png, fig_rules_alone.png
"""
import json
import os
import sys

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

from nids.analyzer import AXIS, GRID, INK, INK2, MUTED, SERIES, SURFACE  # noqa: E402

from nids.paths import ROOT as HERE  # repository root


def _style(ax, grid_axis='y'):
    ax.set_facecolor(SURFACE)
    for side in ('top', 'right', 'left'):
        ax.spines[side].set_visible(False)
    ax.spines['bottom'].set_color(AXIS)
    ax.tick_params(colors=MUTED, labelcolor=INK2, length=0, labelsize=9)
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def fig_family_policy(data, out):
    by = {r['label']: r for r in data['results']}
    segs = list(data['results'][0]['segments'])
    seg_title = {'dev': 'DEV segment (PortScan)', 'test': 'TEST segment (DDoS)', 'all': 'whole capture'}
    fams = ['count', 'behaviour', 'all']
    fig, axes = plt.subplots(1, len(segs), figsize=(5.2 * len(segs), 3.6), facecolor=SURFACE, sharey=True)
    axes = axes if len(segs) > 1 else [axes]
    w = 0.34
    for ax, seg in zip(axes, segs):
        _style(ax)
        for j, pol in enumerate(('fixed', 'adaptive')):
            xs = [i + (j - 0.5) * (w + 0.03) for i in range(len(fams))]
            vals = [by[f'{f} / {pol}']['segments'][seg]['f1'] * 100 for f in fams]
            ax.bar(xs, vals, width=w, color=SERIES[j], label=f'{pol} thresholds')
            for x, v in zip(xs, vals):
                ax.text(x, v + 1.5, f'{v:.0f}', ha='center', va='bottom', fontsize=8.5, color=INK2)
        ax.set_xticks(range(len(fams)))
        ax.set_xticklabels([f'{f} rules' for f in fams], fontsize=9.5, color=INK)
        ax.set_ylim(0, 105)
        ax.set_title(seg_title.get(seg, seg), loc='left', fontsize=10, color=INK)
    axes[0].set_ylabel('F1 (%), per-second scoring', color=INK2, fontsize=9)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, frameon=False, fontsize=9, labelcolor=INK2, loc='upper right', ncols=2)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def fig_rules_alone(data, out):
    rows = [r for r in data['results'] if r['group'] == 'single']
    wins = list(rows[0]['windows'])
    labels = [r['label'].replace('only ', '') for r in rows]
    if len(wins) > len(SERIES):
        return _rules_alone_panels(rows, wins, labels, out)
    fig, ax = plt.subplots(figsize=(7.2, 0.5 * len(rows) + 1.2), facecolor=SURFACE)
    _style(ax, 'x')
    h = 0.36
    for j, wname in enumerate(wins[:3]):
        ys = [len(rows) - 1 - i + (0.5 - j) * (h + 0.02) for i in range(len(rows))]
        vals = [r['windows'][wname]['recall'] * 100 for r in rows]
        ax.barh(ys, vals, height=h, color=SERIES[j], label=f'{wname} recall')
        for y, v in zip(ys, vals):
            if v > 0:
                ax.text(v + 1, y, f'{v:.0f}', va='center', fontsize=8, color=INK2)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(labels[::-1], fontsize=9.5, color=INK)
    ax.set_xlim(0, 105)
    ax.set_xlabel('share of attacker-active seconds detected (%)', color=INK2, fontsize=9)
    ax.set_title('Each rule on its own (fixed thresholds)', loc='left', fontsize=10, color=INK)
    ax.legend(frameon=False, fontsize=9, labelcolor=INK2, loc='lower right', bbox_to_anchor=(1, 1.0), ncols=3)
    fig.tight_layout()
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def _rules_alone_panels(rows, wins, labels, out):
    """One panel per attack window, for days with more windows than series colours."""
    fig, axes = plt.subplots(1, len(wins), figsize=(2.3 * len(wins) + 1.6, 0.42 * len(rows) + 1.3),
                             facecolor=SURFACE, sharey=True)
    ys = list(range(len(rows)))[::-1]
    for ax, wname in zip(axes, wins):
        _style(ax, 'x')
        vals = [r['windows'][wname]['recall'] * 100 for r in rows]
        ax.barh(ys, vals, height=0.6, color=SERIES[0])
        for y, v in zip(ys, vals):
            if v > 0:
                ax.text(v + 2, y, f'{v:.0f}', va='center', fontsize=8, color=INK2)
        ax.set_xlim(0, 115)
        ax.set_title(wname, loc='left', fontsize=9.5, color=INK)
    axes[0].set_yticks(ys)
    axes[0].set_yticklabels(labels, fontsize=9.5, color=INK)
    fig.supxlabel('share of attacker-active seconds detected (%)', color=INK2, fontsize=9)
    fig.suptitle('Each rule on its own (fixed thresholds)', x=0.01, ha='left', fontsize=10, color=INK)
    fig.tight_layout()
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def main():
    day = sys.argv[1] if len(sys.argv) > 1 else 'friday'
    d = os.path.join(HERE, 'results', day)
    with open(os.path.join(d, 'results.json')) as f:
        data = json.load(f)
    fig_family_policy(data, os.path.join(d, 'fig_family_policy.png'))
    fig_rules_alone(data, os.path.join(d, 'fig_rules_alone.png'))
    print(f'wrote {d}/fig_family_policy.png and fig_rules_alone.png')


if __name__ == '__main__':
    main()
