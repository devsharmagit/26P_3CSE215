"""
Check a day's ground truth (days.py) against the capture before using it for evaluation.

    python -m experiments.explore_day wednesday

Prints, per minute, what the configured attacker sends (packets, SYNs, distinct ports, targets) and which
configured attack window that minute falls in, plus the busiest external -> home sources of the day.
If the attacker's activity does not line up with the windows in days.py, fix days.py first.
"""
import datetime
import sys
from collections import Counter, defaultdict

from nids import pcapng_reader as pr
from nids.days import ADT, DAYS


def main():
    day = DAYS[sys.argv[1] if len(sys.argv) > 1 else 'wednesday']
    if day.relative:
        sys.exit('synthetic windows come from the generator; nothing to verify')
    path = day.capture()
    att = {int.from_bytes(bytes(int(x) for x in a.split('.')), 'big') for a in day.attackers}
    home = 0xC0A8  # 192.168/16
    per_min = defaultdict(lambda: [0, 0, set(), Counter()])
    inbound = Counter()
    first = last = None
    for ts, src, dst, proto, sp, dp, fl, _len in pr.iter_any(path):
        if first is None:
            first = ts
        last = ts
        if (dst >> 16) == home and (src >> 16) != home:
            inbound[src] += 1
        if src in att:
            m = per_min[int(ts // 60)]
            m[0] += 1
            if proto == 6 and (fl & 0x12) == 0x02:
                m[1] += 1
                m[2].add(dp)
            m[3][pr.ip_to_str(dst)] += 1
    fmt = lambda t: datetime.datetime.fromtimestamp(t, ADT).strftime('%H:%M')
    print(f'{day.name}: {fmt(first)} -> {fmt(last)} ADT; attacker(s) {", ".join(sorted(day.attackers))}')
    print('busiest external -> home sources:', [(pr.ip_to_str(s), n) for s, n in inbound.most_common(6)])
    print('\nminute  packets   SYNs  ports  top target          configured window')
    for m in sorted(per_min):
        pk, syn, ports, tg = per_min[m]
        if pk < 20:
            continue
        t = m * 60
        win = next((w.name + ('' if w.in_scope else ' (out of scope)') for w in day.windows if w.start <= t + 59 and t <= w.end), '-')
        print(f'{fmt(t)}  {pk:>8,} {syn:>6,} {len(ports):>6}  {tg.most_common(1)[0][0]:<18}  {win}')


if __name__ == '__main__':
    main()
