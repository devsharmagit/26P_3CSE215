"""
Revision 3 (step 8): the Table III configurations must still reproduce exactly. Same comparison as
`window_matching.py reproduce` (full score() output vs results/<day>/results.json, unrounded), written to a new folder so
the R2 file is not overwritten.

    python -m experiments.revision3_check      # writes results/revision3_check/table3_reproduction.md
"""
import json
import os
import sys

from experiments.window_matching import DAY_NAMES, TABLE3, run_all, same

from nids.paths import ROOT  # noqa: E402  (repository root)


def main():
    out, wall = run_all([(d, c) for d in DAY_NAMES for c in TABLE3])
    L = ['# Revision 3 (step 8): Table III configurations reproduce exactly', '',
         'Reproduce: `python -m experiments.revision3_check`. Full score() output vs `results/<day>/results.json`',
         '(unrounded). In the paper the main grid is Table II.', '',
         '| Day | Configuration | identical |', '|---|---|---|']
    ok = True
    order = [c[0] for c in TABLE3]
    for r in sorted(out, key=lambda r: (r['day'], order.index(r['label']))):
        old = {x['label']: x for x in json.load(open(os.path.join(ROOT, 'results', r['day'], 'results.json')))['results']}
        eq = same(r, old[r['label']])
        ok &= eq
        L.append(f"| {r['day']} | {r['label']} | {'yes' if eq else '**NO**'} |")
    L += ['', f'All identical: **{"yes" if ok else "NO"}** (wall {wall:.0f} s, 8 processes).']
    d = os.path.join(ROOT, 'results', 'revision3_check')
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'table3_reproduction.md'), 'w').write('\n'.join(L) + '\n')
    print(L[-1])
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
