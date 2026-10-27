"""
Score Zeek scan.zeek notices with OUR scoring code (experiments.Truth + experiments.score), task T03.

Every Scan::* notice in notice.log becomes detections (time, scanner address, score 1, ['zeek_scan'])
under two conversions, which are reported separately and never mixed:

  strict  each notice covers only its own second (time = notice ts).
  epoch   each notice also covers the preceding `interval` seconds for the same source (ts - k, k = 0..interval),
          where interval is the configured epoch of the detector that raised it (port_scan_interval for
          Scan::Port_Scan, addr_scan_interval for Scan::Address_Scan). A summary notice describes a whole
          epoch, so this credits Zeek for the epoch it summarises. This is GENEROUS to Zeek: it back-dates
          detections the notice could not have raised before ts. Under 'epoch' the time to first detection
          that score() returns is back-dated too, so the time-to-first-true-alert we report is always the
          STRICT one (the real notice time).

Usage (from the repository root; output folders are relative to the data folder, see nids/paths.py):
  python -m baselines.zeek.eval_zeek friday    default=zeek/out_default matched=zeek/out_matched
  python -m baselines.zeek.eval_zeek wednesday wednesday_default=zeek/out_wednesday_default
  python -m baselines.zeek.eval_zeek friday --tag asshipped default_asshipped=zeek/out_default_asshipped ...
Writes results/zeek_baseline/<day>[_<tag>]_scores.json and prints markdown tables.
"""
import json
import os
import sys
from collections import Counter

from experiments.grid import Truth, score
from nids.days import DAYS
from nids.paths import DATA, ROOT

OUT = os.path.join(ROOT, 'results', 'zeek_baseline')

# Epochs of the two configurations (seconds), as set in config_default.zeek / config_matched.zeek.
# These are the script defaults (5min) except the port-scan epoch of MATCHED (60sec).
INTERVALS = {
    'default': {'Scan::Port_Scan': 300, 'Scan::Address_Scan': 300},
    'matched': {'Scan::Port_Scan': 60, 'Scan::Address_Scan': 300},
    'wednesday_default': {'Scan::Port_Scan': 300, 'Scan::Address_Scan': 300},
    # Zeek 9 as shipped (no sumstats_epoch_compat.zeek): epochs never roll over, so these nominal intervals are
    # what the configuration asked for, not what Zeek used. Diagnostic only.
    'default_asshipped': {'Scan::Port_Scan': 300, 'Scan::Address_Scan': 300},
    'matched_asshipped': {'Scan::Port_Scan': 60, 'Scan::Address_Scan': 300},
}


def read_zeek_log(path):
    """Rows of a Zeek ASCII (TSV) log as dicts; [] if the file does not exist (Zeek writes no empty logs)."""
    if not os.path.exists(path):
        return []
    fields, rows = None, []
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if line.startswith('#fields'):
                fields = line.split('\t')[1:]
            elif line and not line.startswith('#'):
                rows.append(dict(zip(fields, line.split('\t'))))
    return rows


def notices(out_dir):
    return [r for r in read_zeek_log(os.path.join(out_dir, 'notice.log')) if r['note'].startswith('Scan::')]


def to_dets(rows, conversion, intervals):
    dets = []
    for r in rows:
        ts, src = float(r['ts']), r['src']
        if conversion == 'strict':
            dets.append((ts, src, 1, ['zeek_scan']))
        else:
            for k in range(intervals[r['note']] + 1):
                dets.append((ts - k, src, 1, ['zeek_scan']))
    dets.sort(key=lambda d: d[0])
    return dets


def main():
    args = sys.argv[1:]
    tag = ''
    if '--tag' in args:
        i = args.index('--tag')
        tag = '_' + args[i + 1]
        del args[i:i + 2]
    day = args[0]
    runs = dict(a.split('=', 1) for a in args[1:])
    truth = Truth(DAYS[day], DAYS[day].capture())
    attackers = DAYS[day].attackers
    res = {'day': day, 'positives': {w: len(s) for w, s in truth.active.items()}, 'hours': truth.hours, 'runs': {}}
    for name, d in runs.items():
        d = os.path.join(DATA, d) if not os.path.isabs(d) else d
        rows = notices(d)
        sup = [r for r in read_zeek_log(os.path.join(d, 'scan_suppressed.log'))]
        att_rows = [r for r in rows if r['src'] in attackers]
        run = {'out_dir': os.path.relpath(d, DATA),
               'notices': len(rows), 'notices_attacker': len(att_rows), 'notices_other': len(rows) - len(att_rows),
               'notices_by_type': dict(Counter(r['note'] for r in rows)),
               'notice_sources': dict(Counter(r['src'] for r in rows).most_common(20)),
               'attacker_notices': [{'ts': float(r['ts']), 'note': r['note'], 'dst': r['dst'], 'msg': r['msg']}
                                    for r in att_rows],
               'suppressed': len(sup), 'suppressed_attacker': sum(1 for r in sup if r['src'] in attackers),
               'suppressed_other': sum(1 for r in sup if r['src'] not in attackers),
               'suppressed_by_type': dict(Counter(r['note'] for r in sup)),
               'conversions': {}}
        for conv in ('strict', 'epoch'):
            run['conversions'][conv] = score(truth, to_dets(rows, conv, INTERVALS[name]))
        # POST-HOC, informational only (not one of the two pre-registered configurations): the same run if the
        # notices that Zeek's default 1 h suppression swallowed had been logged too.
        if sup:
            run['posthoc_with_suppressed'] = {conv: score(truth, to_dets(rows + sup, conv, INTERVALS[name]))
                                              for conv in ('strict', 'epoch')}
            run['suppressed_ts'] = [(float(r['ts']), r['note'], r['src']) for r in sup]
        res['runs'][name] = run
    os.makedirs(OUT, exist_ok=True)
    json.dump(res, open(os.path.join(OUT, f'{day}{tag}_scores.json'), 'w'), indent=1)

    # ---- markdown
    pct = lambda x: f'{100 * x:.1f}'  # noqa: E731
    if day == 'friday':
        print('| Config | Conversion | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h '
              '| PortScan recall | DDoS recall | TTD PortScan (s) | TTD DDoS (s) | notices attacker / others |')
        print('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
        for name, run in res['runs'].items():
            strict = run['conversions']['strict']
            for conv, sc in run['conversions'].items():
                d, t, w = sc['segments']['dev'], sc['segments']['test'], sc['windows']
                ttd = {k: strict['windows'][k]['ttd'] for k in w}   # always the real notice time
                f = lambda v: '-' if v is None else f'{v:.0f}'  # noqa: E731
                print(f"| {name} | {conv} | {pct(d['precision'])} | {pct(d['recall'])} | {pct(d['f1'])} | "
                      f"{d['fp_per_hour']:.1f} | {pct(t['precision'])} | {pct(t['recall'])} | {pct(t['f1'])} | "
                      f"{t['fp_per_hour']:.1f} | {pct(w['PortScan']['recall'])} | {pct(w['DDoS']['recall'])} | "
                      f"{f(ttd['PortScan'])} | {f(ttd['DDoS'])} | {run['notices_attacker']} / {run['notices_other']} |")
    else:
        print('| Config | Conversion | notices attacker / others | FP seconds | FP seconds per hour | hours |')
        print('|---|---|---|---|---|---|')
        for name, run in res['runs'].items():
            for conv, sc in run['conversions'].items():
                a = sc['segments']['all']
                print(f"| {name} | {conv} | {run['notices_attacker']} / {run['notices_other']} | {a['fp_secs']} | "
                      f"{a['fp_per_hour']:.2f} | {truth.hours['all']:.2f} |")
    if day == 'friday':
        print('\nOur rows, copied programmatically from results/friday/results.md (line number = file line) and '
              'ttd from results/friday/results.json (by_score["1"].windows):')
        ours = ('count / fixed', 'behaviour / fixed', 'only rejected_probes', 'only port_sweep')
        md = os.path.join(ROOT, 'results', 'friday', 'results.md')
        js = json.load(open(os.path.join(ROOT, 'results', 'friday', 'results.json')))
        ttd = {r['label']: r['by_score']['1']['windows'] for r in js['results'] if r['label'] in ours}
        seen = set()
        for i, line in enumerate(open(md), 1):
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            if cells and cells[0] in ours and cells[0] not in seen:
                seen.add(cells[0])
                w = ttd[cells[0]]
                f = lambda v: '-' if v is None else f'{v:.0f}'  # noqa: E731
                print(f"results.md:{i} {line.strip()}  ttd PortScan={f(w['PortScan']['ttd'])} s, "
                      f"DDoS={f(w['DDoS']['ttd'])} s")
    print()
    for name, run in res['runs'].items():
        print(f"{name}: notices by type {run['notices_by_type']}; suppressed {run['suppressed']} "
              f"(attacker {run['suppressed_attacker']}, others {run['suppressed_other']}, by type {run['suppressed_by_type']})")
        print(f"  notice sources: {run['notice_sources']}")
        for a in run['attacker_notices']:
            print(f"  attacker notice {a['ts']:.3f} {a['note']} {a['msg']}")
        for ts, note, src in run.get('suppressed_ts', []):
            print(f"  suppressed {ts:.3f} {note} {src}")
        for conv, sc in run.get('posthoc_with_suppressed', {}).items():
            d, w = sc['segments'][list(sc['segments'])[0]], sc['windows']
            print(f"  POST-HOC incl. suppressed [{conv}] first segment P={pct(d['precision'])} R={pct(d['recall'])} "
                  f"F1={pct(d['f1'])} FP/h={d['fp_per_hour']:.1f} windows=" +
                  str({k: (v['covered'], round(100 * v['recall'], 1)) for k, v in w.items()}))
        for conv, sc in run['conversions'].items():
            print(f"  [{conv}] fp_top_sources={sc['fp_top_sources']} windows={sc['windows']}")


if __name__ == '__main__':
    main()
