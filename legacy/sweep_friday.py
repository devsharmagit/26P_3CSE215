"""
Phase F: hyper-parameter sensitivity, ablation and held-out check on the Friday CICIDS2017 capture.

Usage:  python3 sweep_friday.py            (needs friday.cache, see pcapng_reader.py; ~3-5 min on 8 cores)
Output: sweep_results.json + a printed report.

Scoring unit = one second. Positive seconds = seconds in an attack window in which the attacker
(172.16.0.1) sent traffic. An alert second is a TP if the alert is attributed to the attacker inside a
window (+5 s slack), otherwise a FP (any alert attributed to another source). Per-second precision,
recall and F1 are computed separately for two disjoint time segments:
    DEV  : 08:59-15:40  (contains the PortScan, plus benign traffic)
    TEST : 15:40-17:03  (contains the DDoS, plus benign traffic)
"Held-out" protocol: pick the best setting on DEV, report it on TEST, and vice versa (2-fold).
Because DEV and TEST hold different attack types, a setting that only helps one attack type shows up as a
drop on the other segment.
"""
import os
import datetime
import json
import time
from multiprocessing import Pool

from legacy import adaptive_engine
from nids import pcapng_reader as pr
from nids.paths import DATA
from legacy import rule_engine
from legacy.adaptive_engine import AdaptiveRuleEngine
from legacy.rule_engine import StaticRuleEngine

CACHE = os.path.join(DATA, 'friday.cache')
ADT = datetime.timezone(datetime.timedelta(hours=-3))
ATTACKER = '172.16.0.1'
ATTACKER_INT = int.from_bytes(bytes(int(x) for x in ATTACKER.split('.')), 'big')
SLACK = 5.0


def adt(h, m, s=0):
    return datetime.datetime(2017, 7, 7, h, m, s, tzinfo=ADT).timestamp()


WINDOWS = {'portscan': (adt(13, 55), adt(15, 29)), 'ddos': (adt(15, 56), adt(16, 17, 59))}
SPLIT = adt(15, 40)
SEGMENTS = ('dev', 'test')


def seg(ts):
    return 'dev' if ts < SPLIT else 'test'


def window_of(ts):
    for n, (a, b) in WINDOWS.items():
        if a <= ts <= b + SLACK:
            return n
    return None


_ACTIVE = None  # attacker-active seconds per segment (computed once per process)


def active_seconds():
    global _ACTIVE
    if _ACTIVE is None:
        act = {'dev': set(), 'test': set()}
        first = last = None
        for ts, src, *_ in pr.iter_cache(CACHE):
            if first is None:
                first = ts
            last = ts
            if src == ATTACKER_INT:
                for a, b in WINDOWS.values():
                    if a <= ts <= b:
                        act[seg(ts)].add(int(ts))
        hours = {'dev': (SPLIT - first) / 3600, 'test': (last - SPLIT) / 3600}
        _ACTIVE = (act, hours)
    return _ACTIVE


def run_config(job):
    """job = (label, kind, ctor_kwargs, attr_overrides). Returns metrics per segment."""
    label, kind, kw, attrs = job
    act, hours = active_seconds()
    cls, mod = (StaticRuleEngine, rule_engine) if kind == 'static' else (AdaptiveRuleEngine, adaptive_engine)
    alerts = []
    mod.generate_alert = lambda ts, rule, src, details: alerts.append((ts, rule, src))
    eng = cls(**kw)
    for k, v in attrs.items():
        setattr(eng, k, v)
    for rec in pr.iter_cache(CACHE):
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    eng.flush()
    tp_secs = {'dev': set(), 'test': set()}
    fp_secs = {'dev': set(), 'test': set()}
    first_alert = {}
    for ts, rule, src in alerts:
        w = window_of(ts) if src == ATTACKER else None
        if w:
            tp_secs[seg(ts)].add(int(ts))
            first_alert.setdefault(w, ts - WINDOWS[w][0])
        else:
            fp_secs[seg(ts)].add(int(ts))
    out = {'label': label, 'alerts': len(alerts), 'ttd': first_alert}
    for s in SEGMENTS:
        tp = len(tp_secs[s] & act[s])
        pos = len(act[s])
        fp = len(fp_secs[s])
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / pos if pos else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out[s] = {'tp': tp, 'pos': pos, 'fp_secs': fp, 'fp_per_hour': fp / hours[s], 'precision': prec, 'recall': rec, 'f1': f1}
    return out


def build_jobs():
    jobs = []
    A, S = 'adaptive', 'static'
    base_a = {}
    # ---- ablation (cumulative and single-rule) -------------------------------------------------------
    jobs.append(('abl:static-legacy', S, dict(initiator_only_ports=False, victim_rules=False), {}))
    jobs.append(('abl:static-fixed-ports', S, dict(victim_rules=False), {}))
    jobs.append(('abl:static+victim', S, {}, {}))
    steps = [('syn', ['syn']), ('syn+icmp', ['syn', 'icmp']), ('+half_open', ['syn', 'icmp', 'half_open']),
             ('+entropy', ['syn', 'icmp', 'half_open', 'entropy']), ('+victim (full)', ['syn', 'icmp', 'half_open', 'entropy', 'victim'])]
    for name, rules in steps:
        jobs.append((f'abl:adaptive {name} [freeze]', A, dict(enabled_rules=rules), {}))
    jobs.append(('abl:adaptive full [NO freeze]', A, dict(baseline_freeze=False), {}))
    for r in ['syn', 'icmp', 'half_open', 'entropy', 'victim']:
        jobs.append((f'abl:adaptive only {r}', A, dict(enabled_rules=[r]), {}))
    # ---- one-at-a-time sensitivity (adaptive) ---------------------------------------------------------
    oat = {
        'SYN_MULTIPLIER': [1.5, 2.0, 3.0, 5.0, 8.0],
        'MIN_SYN_THRESHOLD': [25, 50, 75, 100, 200],
        'alpha': [0.05, 0.1, 0.2, 0.4],
        'ENTROPY_THRESHOLD': [2.0, 3.0, 4.0, 5.0, 6.0],
        'MIN_PORTS_FOR_ENTROPY': [5, 10, 20, 50],
        'HALF_OPEN_RATIO_THRESHOLD': [0.5, 0.7, 0.8, 0.9, 0.95],
        'MIN_CONNECTIONS_FOR_RATIO': [10, 20, 50, 100],
        'freeze_seconds': [10.0, 30.0, 60.0, 120.0, 300.0],
        'MIN_VICTIM_PPS': [150, 250, 400, 600, 1000],
        'MIN_VICTIM_CONN_RATE': [32, 48, 64, 96, 128],
        'VICTIM_PPS_MULTIPLIER': [1.5, 3.0, 6.0],
    }
    for k, vals in oat.items():
        for v in vals:
            jobs.append((f'oat:{k}={v}', A, {}, {k: v}))
    # ---- one-at-a-time (static) -----------------------------------------------------------------------
    for k, vals in {'SYN_THRESHOLD': [25, 50, 100, 200, 400], 'PORT_SCAN_THRESHOLD': [10, 20, 50, 100, 200],
                    'VICTIM_PPS_THRESHOLD': [150, 250, 400, 600, 1000], 'VICTIM_CONN_THRESHOLD': [32, 48, 64, 96, 128]}.items():
        for v in vals:
            jobs.append((f'oat-static:{k}={v}', S, {}, {k: v}))
    # ---- 2-D grids for ROC-like trade-off curves -------------------------------------------------------
    for m in [1.5, 2.0, 3.0, 5.0, 8.0]:
        for f in [25, 50, 100, 200]:
            jobs.append((f'grid:SYN_MULTIPLIER={m},MIN_SYN_THRESHOLD={f}', A, {}, {'SYN_MULTIPLIER': m, 'MIN_SYN_THRESHOLD': f}))
    for p in [150, 250, 400, 600, 1000]:
        for c in [32, 48, 64, 96, 128]:
            jobs.append((f'grid:MIN_VICTIM_PPS={p},MIN_VICTIM_CONN_RATE={c}', A, {}, {'MIN_VICTIM_PPS': p, 'MIN_VICTIM_CONN_RATE': c}))
    # de-duplicate by label
    seen, uniq = set(), []
    for j in jobs:
        if j[0] not in seen:
            seen.add(j[0])
            uniq.append(j)
    return uniq


def fmt_row(r):
    d, t = r['dev'], r['test']
    return (f"{r['label']:<58} DEV P={d['precision'] * 100:5.1f} R={d['recall'] * 100:5.1f} F1={d['f1'] * 100:5.1f} FP/h={d['fp_per_hour']:6.1f} | "
            f"TEST P={t['precision'] * 100:5.1f} R={t['recall'] * 100:5.1f} F1={t['f1'] * 100:5.1f} FP/h={t['fp_per_hour']:6.1f}")


def report(results):
    by = {r['label']: r for r in results}
    print('\n================ ABLATION (per-second metrics) ================')
    for r in results:
        if r['label'].startswith('abl:'):
            print(fmt_row(r))
    print('\n================ ONE-AT-A-TIME SENSITIVITY ================')
    for r in results:
        if r['label'].startswith('oat'):
            print(fmt_row(r))
    print('\n================ HELD-OUT CHECK (2-fold) ================')
    cand = [r for r in results if r['label'].startswith(('oat:', 'grid:', 'abl:adaptive full'))]
    for src, dst in (('dev', 'test'), ('test', 'dev')):
        best = max(cand, key=lambda r: (r[src]['f1'], -r[src]['fp_per_hour']))
        default = by['abl:adaptive +victim (full) [freeze]']
        print(f"tuned on {src.upper():<4}: best = {best['label']}\n"
              f"    {src.upper()} F1 {best[src]['f1'] * 100:.1f}% (default {default[src]['f1'] * 100:.1f}%)   ->   held-out {dst.upper()} F1 {best[dst]['f1'] * 100:.1f}% (default {default[dst]['f1'] * 100:.1f}%)")
    print('\n(Segments hold different attack types; DEV = PortScan, TEST = DDoS.)')


def main():
    jobs = build_jobs()
    print(f'{len(jobs)} configurations; running on a process pool...', flush=True)
    active_seconds()
    t0 = time.time()
    with Pool(8) as pool:
        results = []
        for i, r in enumerate(pool.imap_unordered(run_config, jobs), 1):
            results.append(r)
            if i % 10 == 0:
                print(f'  {i}/{len(jobs)} done ({time.time() - t0:.0f}s)', flush=True)
    order = {j[0]: i for i, j in enumerate(jobs)}
    results.sort(key=lambda r: order[r['label']])
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'outputs', 'sweep_results.json'), 'w') as f:
        json.dump(results, f, indent=1)
    report(results)


if __name__ == '__main__':
    main()
