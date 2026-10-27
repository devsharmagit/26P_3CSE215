"""
What the Friday scan campaign sends, per phase: attacker -> victim packets by IP protocol (TCP / UDP / ICMP / other IP
protocols) and distinct TCP destination ports of SYN-only packets. Supports the statement that the slow phases use few
TCP ports and that later phases use UDP and raw IP protocols. Phase boundaries follow the per-minute timeline in
results/zeek_baseline/attacker_conn_timeline.txt.

    python -m experiments.scan_phase_check        # ~30 s; writes results/friday_scan_phases/results.md
"""
import datetime
import os
from collections import Counter, defaultdict

from nids import pcapng_reader as pr
from nids.days import ADT, DAYS

from nids.paths import ROOT  # noqa: E402  (repository root)
A = int.from_bytes(bytes([172, 16, 0, 1]), 'big')
V = int.from_bytes(bytes([192, 168, 10, 50]), 'big')
PHASES = [('13:55-14:17', (13, 55), (14, 17)), ('14:17-14:21', (14, 17), (14, 21)), ('14:51-14:57', (14, 51), (14, 57)),
          ('15:08-15:11', (15, 8), (15, 11)), ('15:11-15:16', (15, 11), (15, 16)), ('15:16-15:29', (15, 16), (15, 29))]
PROTO = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}


def ts(h, m):
    return datetime.datetime(2017, 7, 7, h, m, tzinfo=ADT).timestamp()


def main():
    bounds = [(n, ts(*a), ts(*b)) for n, a, b in PHASES]
    by_proto = defaultdict(Counter)
    ports = defaultdict(set)
    for t, src, dst, proto, sp, dp, fl, _l in pr.iter_any(DAYS['friday'].capture()):
        if src != A or dst != V:
            continue
        for n, a, b in bounds:
            if a <= t < b:
                by_proto[n][PROTO.get(proto, f'IP proto {proto}')] += 1
                if proto == 6 and fl & 0x02 and not fl & 0x10:
                    ports[n].add(dp)
    L = ['# Friday scan phases: attacker -> victim traffic by protocol', '',
         'Reproduce: `python -m experiments.scan_phase_check`. Times ADT. Counts are packets 172.16.0.1 -> 192.168.10.50.', '',
         '| phase | packets by protocol | distinct TCP ports in SYN-only packets |', '|---|---|---|']
    for n, _a, _b in bounds:
        L.append(f"| {n} | {', '.join(f'{k} {v:,}' for k, v in by_proto[n].most_common())} | {len(ports[n])} |")
    d = os.path.join(ROOT, 'results', 'friday_scan_phases')
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'results.md'), 'w').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
