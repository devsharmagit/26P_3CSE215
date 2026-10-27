"""
Phase G: throughput and memory of the rule engines on the full Friday capture (9.9M packets).

Each configuration runs in its own process so peak RSS (ru_maxrss) is isolated.
  parse-only      : cache -> feature dict, no engine (the floor)
  static          : StaticRuleEngine
  adaptive        : AdaptiveRuleEngine (decay + pruning + freeze)
  adaptive-nodecay: same engine with decay/pruning disabled (reproduces the original unbounded growth)
Also samples the engine's state-container sizes every 1M packets, and measures the scapy path for scale.
Usage: python3 perf_friday.py     (needs friday.cache)
"""
import os
import multiprocessing as mp
import resource
import sys
import time

from legacy import adaptive_engine
from nids import pcapng_reader as pr
from nids.paths import DATA
from legacy import rule_engine

CACHE = os.path.join(DATA, 'friday.cache')


def state_size(eng):
    n = 0
    for name in ('connections', 'connection_timestamps', 'src_connections', 'port_frequencies', 'historical_syn_avg',
                 'historical_icmp_avg', 'historical_victim_pps', 'historical_victim_conn', 'frozen_until'):
        obj = getattr(eng, name, None)
        if obj is not None:
            n += len(obj)
    n += sum(len(v) for v in getattr(eng, 'port_frequencies', {}).values())
    n += sum(len(v) for v in getattr(eng, 'src_connections', {}).values())
    return n


def worker(kind, q):
    adaptive_engine.generate_alert = lambda *a, **k: None
    rule_engine.generate_alert = lambda *a, **k: None
    base_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    eng = None
    if kind == 'static':
        eng = rule_engine.StaticRuleEngine()
    elif kind == 'adaptive':
        eng = adaptive_engine.AdaptiveRuleEngine()
    elif kind == 'adaptive-nodecay':
        eng = adaptive_engine.AdaptiveRuleEngine()
        eng.port_decay_factor = 1.0
        eng.connection_timeout = 1e12
    n = 0
    timeline = []
    t0 = time.time()
    for rec in pr.iter_cache(CACHE):
        if rec[3] not in (1, 6, 17):
            continue
        f = pr.to_features(rec)
        if eng is not None:
            eng.process_packet(f)
        n += 1
        if eng is not None and kind != 'static' and n % 1_000_000 == 0:
            timeline.append((n, state_size(eng)))
    if eng is not None:
        eng.flush()
    dt = time.time() - t0
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    q.put({'kind': kind, 'packets': n, 'seconds': dt, 'pps': n / dt, 'peak_rss_mb': rss / 1e6 if sys.platform == 'darwin' else rss / 1e3,
           'base_rss_mb': base_rss / 1e6 if sys.platform == 'darwin' else base_rss / 1e3,
           'timeline': timeline, 'final_state': state_size(eng) if eng is not None and kind != 'static' else 0})


def scapy_rate(limit=100_000):
    """Throughput of the original scapy path on the first packets of the raw pcap (reference only)."""
    try:
        from scapy.all import PcapNgReader
        from nids.packet_parser import parse_packet
    except Exception as e:  # scapy not available in this interpreter
        return None
    eng = adaptive_engine.AdaptiveRuleEngine()
    n = 0
    t0 = time.time()
    with PcapNgReader(os.path.join(DATA, 'Friday-WorkingHours.pcap')) as r:
        for p in r:
            ft = parse_packet(p)
            if ft:
                eng.process_packet(ft)
            n += 1
            if n >= limit:
                break
    return n / (time.time() - t0)


if __name__ == '__main__':
    mp.set_start_method('spawn')
    res = []
    for kind in ('parse-only', 'static', 'adaptive', 'adaptive-nodecay'):
        q = mp.Queue()
        p = mp.Process(target=worker, args=(kind, q))
        p.start()
        r = q.get()
        p.join()
        res.append(r)
        print(f"{kind:<18} {r['packets']:>10,} pkts  {r['seconds']:6.1f}s  {r['pps']:>11,.0f} pkt/s  peak RSS {r['peak_rss_mb']:7.1f} MB  final state entries {r['final_state']:>9,}", flush=True)
    print('\nState-container entries every 1M packets:')
    for r in res:
        if r['timeline']:
            print(f"  {r['kind']:<18}", [f'{s:,}' for _n, s in r['timeline']])
    sr = scapy_rate()
    if sr:
        print(f'\nscapy path (PcapNgReader + parse_packet + adaptive engine), first 100k packets: {sr:,.0f} pkt/s')
    else:
        print('\n(scapy not importable here; run with ./venv/bin/python to include the scapy reference)')
