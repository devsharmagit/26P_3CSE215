"""
Revision 2 (R7) check: time to detect of the baselines under the Table V definition (first TRUE alert: an alert on the
attacker in a second with attacker -> victim traffic), next to the value stored in their results files, which came from
experiments.score()'s 'ttd' (first attacker alert anywhere in the window + 5 s slack).

    python -m experiments.ttd_check        # writes results/ttd_check/results.md
"""
import os

from nids.paths import ROOT  # noqa: E402  (repository root)
from nids.days import DAYS  # noqa: E402
from baselines.suricata.eval_suricata_v2 import VIEWS, load  # noqa: E402
from experiments.grid import Truth, score  # noqa: E402


def first_true(truth, dets, name):
    start = {n: s for n, s, e, i in truth.windows}[name]
    ts = [t for t, src, _s, _r in dets if (w := truth.window_of(src, t)) and w[0] == name and int(t) in truth.active[name]]
    return min(ts) - start if ts else None


def main():
    truth = Truth(DAYS['friday'], DAYS['friday'].capture())
    L = ['# TTD check: first true alert vs first attacker alert (Friday baselines)', '',
         'Reproduce: `python -m experiments.ttd_check`. "stored" = `score()` ttd as printed in',
         '`results/suricata_rescored/results.md`; "first true alert" = the definition of Table V and `derived_tables.py`.', '',
         '| Detector | attack | stored TTD (s) | first true alert (s) |', '|---|---|---|---|']
    f = lambda v: '–' if v is None else f'{v:.1f}'
    for label, path, prefixes in VIEWS:
        dets, _n, _ns = load(path, prefixes)
        r = score(truth, dets, 1)
        for w in ('PortScan', 'DDoS'):
            L.append(f"| Suricata: {label} | {w} | {f(r['windows'][w]['ttd'])} | {f(first_true(truth, dets, w))} |")
    d = os.path.join(ROOT, 'results', 'ttd_check')
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'results.md'), 'w').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
