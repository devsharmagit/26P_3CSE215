"""
Evaluate StaticRuleEngine vs AdaptiveRuleEngine on the raw CICIDS2017 Friday capture.

Prerequisite (one pass, ~10 s):  python -m nids.pcapng_reader data/Friday-WorkingHours.pcap data/friday.cache

Ground truth (verified against the capture itself, see explore_friday.py):
  * Attacker: 172.16.0.1 (the attack machines appear behind this NAT address) -> victim 192.168.10.50
  * PortScan (Nmap runs):  13:55-15:29 ADT   (only traffic from 172.16.0.1 counts)
  * DDoS (LOIC):           15:56-16:17 ADT
  * Timestamps in the pcap are UTC; CIC's published schedule is ADT (UTC-3).
Bot traffic (Ares C2 to 205.174.165.73, ~10:02-11:02 ADT) is NOT a rate/scan attack and is out of scope.
Every alert from a source other than 172.16.0.1 is counted as a false positive.
"""
import os
import datetime
import sys
import time
from collections import Counter, defaultdict

from legacy import adaptive_engine
from nids import pcapng_reader as pr
from nids.paths import DATA
from legacy import rule_engine
from legacy.adaptive_engine import AdaptiveRuleEngine
from legacy.rule_engine import StaticRuleEngine

CACHE = os.path.join(DATA, 'friday.cache')
ADT = datetime.timezone(datetime.timedelta(hours=-3))
ATTACKER = '172.16.0.1'


def adt(h, m, s=0):
    return datetime.datetime(2017, 7, 7, h, m, s, tzinfo=ADT).timestamp()


ATTACK_WINDOWS = {
    'PortScan (Nmap)': (adt(13, 55), adt(15, 29)),
    'DDoS (LOIC)': (adt(15, 56), adt(16, 17, 59)),
}
SLACK = 5.0  # seconds of tolerance after a window for alerts emitted on window rollover


def fmt(ts):
    return datetime.datetime.fromtimestamp(ts, ADT).strftime('%H:%M:%S')


def run(engine_cls, module, limit=None, **kw):
    alerts = []  # (ts, rule, src)

    def capture(timestamp, rule_name, src_ip, details):
        alerts.append((timestamp, rule_name, src_ip))

    orig = module.generate_alert
    module.generate_alert = capture
    t0 = time.time()
    n = 0
    try:
        eng = engine_cls(**kw)
        for rec in pr.iter_cache(CACHE):
            proto = rec[3]
            if proto not in (1, 6, 17):
                continue
            eng.process_packet(pr.to_features(rec))
            n += 1
            if limit and n >= limit:
                break
        eng.flush()
    finally:
        module.generate_alert = orig
    return alerts, n, time.time() - t0


def attacker_activity():
    """Seconds in which the attacker sent packets, per attack window; and benign span."""
    secs = defaultdict(set)
    first = last = None
    for ts, src, _d, proto, *_ in pr.iter_cache(CACHE):
        if first is None:
            first = ts
        last = ts
        if src == ATTACKER_INT:
            for name, (a, b) in ATTACK_WINDOWS.items():
                if a <= ts <= b:
                    secs[name].add(int(ts))
    return secs, first, last


ATTACKER_INT = int.from_bytes(bytes(int(x) for x in ATTACKER.split('.')), 'big')


def analyse(name, alerts, secs, first, last):
    print(f'\n=== {name} ===')
    tp = fp = 0
    fp_rules, fp_src = Counter(), Counter()
    tp_rules = Counter()
    alert_secs = defaultdict(set)
    first_alert = {}
    for ts, rule, src in alerts:
        in_win = None
        if src == ATTACKER:
            for wname, (a, b) in ATTACK_WINDOWS.items():
                if a <= ts <= b + SLACK:
                    in_win = wname
        if in_win:
            tp += 1
            tp_rules[(in_win, rule)] += 1
            alert_secs[in_win].add(int(ts))
            first_alert.setdefault(in_win, ts)
        else:
            fp += 1
            fp_rules[rule] += 1
            fp_src[src] += 1
    hours = (last - first) / 3600.0
    print(f'Total alerts: {len(alerts)}   attack-window alerts: {tp}   other alerts (FP): {fp}   ({fp / hours:.1f} FP alerts/hour over {hours:.2f} h)')
    for wname, (a, b) in ATTACK_WINDOWS.items():
        active = secs[wname]
        covered = len(active & alert_secs[wname])
        ttd = (first_alert[wname] - a) if wname in first_alert else None
        rec = covered / len(active) if active else 0
        print(f'  {wname:<16} attacker-active seconds={len(active):>5}  seconds with an alert={covered:>5}  '
              f'second-level recall={rec * 100:5.1f}%  first alert at {fmt(first_alert[wname]) if ttd is not None else "NEVER"}'
              f'{"  (+%.0fs after window start)" % ttd if ttd is not None else ""}')
    for (w, rule), c in sorted(tp_rules.items()):
        print(f'    TP  {w:<16} {rule:<22} {c}')
    prec = tp / (tp + fp) if tp + fp else 0
    print(f'  Alert-level precision: {prec * 100:.2f}%')
    print(f'  FP by rule: {dict(fp_rules)}')
    print(f'  Distinct benign/other sources alerted: {len(fp_src)}  top: {fp_src.most_common(6)}')
    return {'tp': tp, 'fp': fp, 'fp_src': fp_src, 'fp_rules': fp_rules}


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    secs, first, last = attacker_activity()
    print(f'Capture span {fmt(first)} -> {fmt(last)} ADT')
    for wname, s in secs.items():
        print(f'  attacker-active seconds in {wname}: {len(s)}')
    res = {}
    legacy = {'initiator_only_ports': False, 'victim_rules': False}
    fix_ports = {'initiator_only_ports': True, 'victim_rules': False}
    configs = (('StaticRuleEngine (legacy)', StaticRuleEngine, rule_engine, legacy),
               ('AdaptiveRuleEngine (legacy)', AdaptiveRuleEngine, adaptive_engine, dict(legacy, baseline_freeze=False)),
               ('StaticRuleEngine (+port fix)', StaticRuleEngine, rule_engine, fix_ports),
               ('AdaptiveRuleEngine (+port fix)', AdaptiveRuleEngine, adaptive_engine, dict(fix_ports, baseline_freeze=False)),
               ('AdaptiveRuleEngine (+port fix +baseline freeze)', AdaptiveRuleEngine, adaptive_engine, dict(fix_ports, baseline_freeze=True)),
               ('StaticRuleEngine (+port fix +victim rules)', StaticRuleEngine, rule_engine, {}),
               ('AdaptiveRuleEngine (all fixes + victim rules)', AdaptiveRuleEngine, adaptive_engine, {}))
    for name, cls, mod, kw in configs:
        alerts, n, dt = run(cls, mod, limit, **kw)
        print(f'\n{name}: processed {n:,} packets in {dt:.0f}s ({n / dt:,.0f} pkt/s)')
        res[name] = analyse(name, alerts, secs, first, last)

if __name__ == '__main__':
    main()
