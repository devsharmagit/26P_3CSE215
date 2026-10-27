"""
Diagnostic: per-minute (ADT) summary of 172.16.0.1 -> 192.168.10.50 connections in a Zeek conn.log, with the
cumulative number of distinct (port, proto) pairs seen in failed states. Explains when a distinct-port
detector can first fire. Usage: python baselines/zeek/conn_timeline.py data/zeek/out_default/conn.log > results/zeek_baseline/attacker_conn_timeline.txt
"""
import collections
import datetime
import sys

ADT = datetime.timezone(datetime.timedelta(hours=-3))
FAILED = {'REJ', 'S0', 'RSTO', 'RSTOS0', 'RSTR', 'RSTRH', 'SH', 'SHR'}
fields, rows = None, []
for line in open(sys.argv[1]):
    if line.startswith('#fields'):
        fields = line.rstrip('\n').split('\t')[1:]
    elif not line.startswith('#'):
        r = dict(zip(fields, line.rstrip('\n').split('\t')))
        if r['id.orig_h'] == '172.16.0.1' and r['id.resp_h'] == '192.168.10.50':
            rows.append(r)
rows.sort(key=lambda r: float(r['ts']))
seen, per = set(), collections.OrderedDict()
for r in rows:
    m = datetime.datetime.fromtimestamp(float(r['ts']), ADT).strftime('%H:%M')
    d = per.setdefault(m, collections.Counter())
    d[r['proto'] + ':' + r['conn_state']] += 1
    if r['conn_state'] in FAILED:
        seen.add((r['id.resp_p'], r['proto']))
    d['cum_distinct_failed_ports'] = len(seen)
print('# minute (ADT, conn start) | connections by proto:conn_state | cumulative distinct failed (port, proto)')
for m, d in per.items():
    c = d.pop('cum_distinct_failed_ports')
    print(m, '|', ', '.join(f'{k}={v}' for k, v in sorted(d.items())), '|', c)
