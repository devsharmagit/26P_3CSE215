"""
Why the header rules miss the slow DoS attacks on Wednesday: per attack, how many TCP connections the attacker opened to
the victim, what share completed the handshake (initiator ACK seen), and the SYN rate per active second.

    python -m experiments.slow_dos_check        # writes results/wednesday_2x2/slow_dos_check.md
"""
import os
import statistics
from collections import Counter

from nids import pcapng_reader as pr
from nids.days import DAYS

from nids.paths import ROOT  # noqa: E402  (repository root)
A = int.from_bytes(bytes([172, 16, 0, 1]), 'big')
V = int.from_bytes(bytes([192, 168, 10, 50]), 'big')


def main():
    day = DAYS['wednesday']
    wins = [w for w in day.windows if w.in_scope]
    stats = {w.name: {'syn': set(), 'ack': set(), 'synps': Counter()} for w in wins}
    for ts, src, dst, proto, sp, dp, fl, _l in pr.iter_any(day.capture()):
        if src != A or dst != V or proto != 6:
            continue
        for w in wins:
            if w.start <= ts <= w.end:
                s = stats[w.name]
                if fl & 0x02 and not fl & 0x10:
                    s['syn'].add((sp, dp))
                    s['synps'][int(ts)] += 1
                elif fl & 0x10 and (sp, dp) in s['syn']:
                    s['ack'].add((sp, dp))
    L = ['# Slow-DoS check (Wednesday, attacker 172.16.0.1 -> 192.168.10.50)', '',
         'Reproduce: `python -m experiments.slow_dos_check`. A connection = (source port, destination port) opened by a',
         'SYN-only packet inside the window; completed = an ACK from the attacker on the same ports was seen afterwards.', '',
         '| Attack | connections opened | completed handshake | median SYN/s (seconds with a SYN) | max SYN/s |', '|---|---|---|---|---|']
    for w in wins:
        s = stats[w.name]
        v = sorted(s['synps'].values())
        L.append(f"| {w.name} | {len(s['syn']):,} | {len(s['ack']) / len(s['syn']) * 100:.1f} % | {statistics.median(v):g} | {v[-1]} |")
    out = os.path.join(ROOT, 'results', 'wednesday_2x2', 'slow_dos_check.md')
    open(out, 'w').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
