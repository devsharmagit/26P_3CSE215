"""
Trace of the adaptive baseline of the victim rules for 192.168.10.50 around the Friday DDoS, for the count/adaptive
setting floor=1, multiplier level 4 of sensitivity.py (m = 4), where TEST F1 drops to ~0. Shows whether the freeze
engages. One row per minute (the first window of each minute), 15:50-16:20 ADT.

    python -m experiments.baseline_trace          # ~1 min; writes results/sensitivity/baseline_trace.md
"""
import datetime
import os

from nids import pcapng_reader as pr
from experiments import sensitivity as S
from nids.days import ADT, DAYS
from nids.engine import RuleEngine

from nids.paths import ROOT  # noqa: E402  (repository root)
VICTIM, ATTACKER = '192.168.10.50', '172.16.0.1'
JOB = {'family': 'count', 'policy': 'adaptive', 'floor': 1, 'level': 4, 'label': 'count / adaptive floor=1 m-level=4'}
START = datetime.datetime(2017, 7, 7, 15, 50, tzinfo=ADT).timestamp()
END = datetime.datetime(2017, 7, 7, 16, 20, tzinfo=ADT).timestamp()
DDOS = DAYS['friday'].windows[1]


def main():
    rs = S.make_rule_set(JOB)
    rules = {r.id: r for r in rs.rules}
    rows, dets = [], []

    class Traced(RuleEngine):
        def _rollover(self):
            t = self.window_start
            if START <= t <= END:
                row = [t, self.victim_pkts.get(VICTIM, 0), self.victim_syns.get(VICTIM, 0)]
                for rid in ('victim_packet_flood', 'victim_conn_flood'):
                    b = self.baseline[rid].get(VICTIM) or 0.0
                    row += [b, max(rules[rid].value, rules[rid].multiplier * b), self.frozen_until[rid].get(VICTIM, 0) > t]
                rows.append(row)
            super()._rollover()

    eng = Traced(rs, on_detection=dets.append)
    for rec in pr.iter_any(DAYS['friday'].capture()):
        if rec[0] > END + 5:
            break
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    fmt = lambda t: datetime.datetime.fromtimestamp(t, ADT).strftime('%H:%M:%S')
    n_att = sum(1 for d in dets if d.src == ATTACKER and DDOS.start <= d.time <= DDOS.end + 5)
    L = [f'# Baseline trace: {JOB["label"]} (Friday, victim {VICTIM})', '',
         'Reproduce: `python -m experiments.baseline_trace`. First window of each minute; thresholds = max(floor, m x baseline).', '',
         f'Detections attributed to the attacker inside the DDoS window (15:56-16:17:59 ADT): **{n_att}**', '',
         '| time (ADT) | victim pkts/s | victim new conn/s | pps baseline | pps threshold | pps frozen | conn baseline | conn threshold | conn frozen |',
         '|---|---|---|---|---|---|---|---|---|']
    last_min = None
    for t, pps, conn, bp, tp, fp, bc, tc, fc in rows:
        m = int(t // 60)
        if m == last_min:
            continue
        last_min = m
        L.append(f'| {fmt(t)} | {pps} | {conn} | {bp:.1f} | {tp:.1f} | {"yes" if fp else "no"} | {bc:.1f} | {tc:.1f} | {"yes" if fc else "no"} |')
    out = os.path.join(ROOT, 'results', 'sensitivity', 'baseline_trace.md')
    open(out, 'w').write('\n'.join(L) + '\n')
    print('wrote', out, 'attacker detections in DDoS window:', n_att)


if __name__ == '__main__':
    main()
