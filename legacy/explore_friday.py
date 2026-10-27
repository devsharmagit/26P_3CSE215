import datetime
from collections import Counter, defaultdict
import os
from nids import pcapng_reader as r
from nids.paths import DATA
ADT = datetime.timezone(datetime.timedelta(hours=-3))
syn_min = defaultdict(Counter); ports_min = defaultdict(lambda: defaultdict(set)); icmp = Counter(); proto=Counter()
first=last=None; src_tot=Counter()
for ts,src,dst,pr,sp,dp,fl in r.iter_cache(os.path.join(DATA, 'friday.cache')):
    if first is None: first=ts
    last=ts; proto[pr]+=1; src_tot[src]+=1
    m=int(ts//60)
    if pr==6 and (fl&0x12)==0x02:
        syn_min[m][src]+=1; ports_min[m][src].add(dp)
    if pr==1: icmp[src]+=1
fmt=lambda t: datetime.datetime.fromtimestamp(t,ADT).strftime('%H:%M:%S')
print('span ADT',fmt(first),'->',fmt(last),'proto',dict(proto))
print('top talkers',[(r.ip_to_str(s),c) for s,c in src_tot.most_common(8)])
print('icmp top',[(r.ip_to_str(s),c) for s,c in icmp.most_common(5)])
# minutes where any src sent >300 SYN or hit >100 distinct dst ports
print('\nminute(ADT)  top SYN src: count / distinct dports')
rows=[]
for m in sorted(syn_min):
    s,c=syn_min[m].most_common(1)[0]
    rows.append((m,r.ip_to_str(s),c,len(ports_min[m][s])))
# compress into runs
run=None
for m,s,c,d in rows:
    hot = c>=300 or d>=100
    key=(s) if hot else None
    if key and run and run[0]==key and m==run[2]+1: run[2]=m; run[3]+=c; run[4]=max(run[4],d)
    else:
        if run: print(f'{r.ip_to_str(0) if False else ""}{run[0]}  {fmt(run[1]*60)} -> {fmt(run[2]*60+59)}  synsTotal={run[3]} maxPortsPerMin={run[4]}')
        run=[key,m,m,c,d] if key else None
if run: print(f'{run[0]}  {fmt(run[1]*60)} -> {fmt(run[2]*60+59)}  synsTotal={run[3]} maxPortsPerMin={run[4]}')
