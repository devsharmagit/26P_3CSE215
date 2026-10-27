"""
Packet analyzer: one pass over a capture -> traffic summary, figures and (optionally) rule detections,
written as a self-contained HTML report.

    python3 main.py analyze -f capture.pcap                      # summary + figures + detections (rules.yaml)
    python3 main.py analyze -f friday.cache --truth friday       # also shade the known attack windows

Output (default report/<capture name>/):
    report.html        everything below in one page (figures embedded)
    summary.json       all numbers in the report
    detections.jsonl   one line per detection (time, source, score, rules, evidence)
    incidents.json     detections grouped per source into incidents
    fig_*.png          the figures, for the paper / slides
"""
import base64
import datetime
import html
import json
import os
import time
from collections import Counter, defaultdict

from nids import pcapng_reader as pr

PROTO_NAMES = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 132: 'SCTP'}
SERVICES = {20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp',
            80: 'http', 88: 'kerberos', 110: 'pop3', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns', 138: 'netbios-dgm',
            139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 389: 'ldap', 443: 'https', 444: 'snpp/https-alt',
            445: 'smb', 465: 'smtps', 514: 'syslog', 587: 'submission', 631: 'ipp', 993: 'imaps', 995: 'pop3s',
            1900: 'ssdp', 3268: 'ldap-gc', 3389: 'rdp', 5353: 'mdns', 5355: 'llmnr', 8080: 'http-alt', 8443: 'https-alt'}
INCIDENT_GAP = 60.0  # detections of one source closer than this belong to one incident

# chart tokens (dataviz reference palette, light surface)
SURFACE, INK, INK2, MUTED, GRID, AXIS = '#fcfcfb', '#0b0b0b', '#52514e', '#898781', '#e1e0d9', '#c3c2b7'
SERIES = ['#2a78d6', '#eb6834', '#1baf7a']   # TCP, UDP, ICMP (validated all-pairs, light)
ACCENT, NEUTRAL_BAR = '#2a78d6', '#b4b2a9'
WINDOW_FILL = '#eb6834'


def _ip_int(ip):
    return int.from_bytes(bytes(int(x) for x in ip.split('.')), 'big')


class Analyzer:
    def __init__(self, home_net=('192.168.0.0/16',)):
        from nids.engine import home_matcher
        self.is_home = home_matcher(list(home_net))
        self.packets = 0
        self.bytes = 0
        self.first = self.last = None
        self.proto_pkts = Counter()
        self.proto_bytes = Counter()
        self.tcp_flags = Counter()
        self.src_pkts = Counter()
        self.src_bytes = Counter()
        self.dst_pkts = Counter()
        self.services = Counter()       # (proto, service port) -> packets
        self.convs = Counter()          # (src, dst) -> packets
        self.per_sec = defaultdict(lambda: [0, 0, 0, 0])  # int second -> [tcp, udp, icmp, other]
        self._home_cache = {}

    def _home(self, ip_int):
        h = self._home_cache.get(ip_int)
        if h is None:
            h = self._home_cache[ip_int] = self.is_home(pr.ip_to_str(ip_int))
        return h

    def add(self, rec):
        ts, src, dst, proto, sport, dport, flags, length = rec
        if self.first is None:
            self.first = ts
        self.last = ts
        self.packets += 1
        self.bytes += length
        self.proto_pkts[proto] += 1
        self.proto_bytes[proto] += length
        self.src_pkts[src] += 1
        self.src_bytes[src] += length
        self.dst_pkts[dst] += 1
        self.convs[(src, dst)] += 1
        row = self.per_sec[int(ts)]
        if proto == 6:
            row[0] += 1
            self.tcp_flags[flags & 0x17] += 1  # FIN SYN RST ACK
            self.services[(6, min(sport, dport))] += 1
        elif proto == 17:
            row[1] += 1
            self.services[(17, min(sport, dport))] += 1
        elif proto == 1:
            row[2] += 1
        else:
            row[3] += 1

    def summary(self, top=10):
        dur = (self.last - self.first) if self.packets else 0.0
        s = lambda n: pr.ip_to_str(n)
        flag_names = {0x02: 'SYN', 0x12: 'SYN-ACK', 0x10: 'ACK (incl. data)', 0x11: 'FIN-ACK', 0x01: 'FIN',
                      0x04: 'RST', 0x14: 'RST-ACK'}
        flags = Counter()
        for k, v in self.tcp_flags.items():
            flags[flag_names.get(k, 'other')] += v
        direction = Counter()
        for (a, b), n in self.convs.items():
            ha, hb = self._home(a), self._home(b)
            direction['internal' if ha and hb else 'outbound' if ha else 'inbound' if hb else 'external'] += n
        peak_sec, peak = max(((t, sum(r)) for t, r in self.per_sec.items()), key=lambda x: x[1], default=(0, 0))
        return {
            'packets': self.packets, 'bytes': self.bytes, 'first': self.first, 'last': self.last,
            'duration_s': dur, 'avg_pps': self.packets / dur if dur else 0.0, 'peak_pps': peak, 'peak_time': peak_sec,
            'hosts': len(set(self.src_pkts) | set(self.dst_pkts)), 'sources': len(self.src_pkts),
            'protocols': [{'protocol': PROTO_NAMES.get(p, str(p)), 'packets': n, 'bytes': self.proto_bytes[p]}
                          for p, n in self.proto_pkts.most_common()],
            'tcp_flags': [{'flags': k, 'packets': v} for k, v in flags.most_common()],
            'direction': [{'direction': k, 'packets': v} for k, v in direction.most_common()],
            'top_sources': [{'ip': s(ip), 'packets': n, 'bytes': self.src_bytes[ip], 'home': self._home(ip)}
                            for ip, n in self.src_pkts.most_common(top)],
            'top_destinations': [{'ip': s(ip), 'packets': n, 'home': self._home(ip)} for ip, n in self.dst_pkts.most_common(top)],
            'top_services': [{'service': f"{SERVICES.get(port, str(port))}/{PROTO_NAMES[proto].lower()}", 'port': port,
                              'packets': n} for (proto, port), n in self.services.most_common(top)],
            'top_conversations': [{'src': s(a), 'dst': s(b), 'packets': n} for (a, b), n in self.convs.most_common(top)],
        }

    def timeline(self, max_points=900):
        if not self.per_sec:
            return 1, []
        t0, t1 = min(self.per_sec), max(self.per_sec)
        need = -(-(t1 - t0 + 1) // max_points)
        bucket = next((b for b in (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600) if b >= need), need)
        rows = defaultdict(lambda: [0, 0, 0, 0])
        for t, r in self.per_sec.items():
            b = t0 + ((t - t0) // bucket) * bucket
            rr = rows[b]
            for i in range(4):
                rr[i] += r[i]
        return bucket, [(b, [v / bucket for v in rows[b]]) for b in range(t0, t1 + 1, bucket)]


def group_incidents(dets, gap=INCIDENT_GAP):
    """Detections -> incidents: consecutive detections of one source with gaps <= `gap` seconds."""
    by_src = defaultdict(list)
    for d in dets:
        by_src[d.src].append(d)
    out = []
    for src, ds in by_src.items():
        ds.sort(key=lambda d: d.time)
        cur = None
        for d in ds:
            if cur is None or d.time - cur['end'] > gap:
                cur = {'src': src, 'start': d.time, 'end': d.time, 'seconds': 0, 'peak_score': 0, 'rules': Counter(),
                       'targets': Counter(), 'evidence': ''}
                out.append(cur)
            cur['end'] = d.time
            cur['seconds'] += 1
            for h in d.hits:
                cur['rules'][h.rule_id] += 1
                if h.target:
                    cur['targets'][h.target] += 1
            if d.score > cur['peak_score']:
                cur['peak_score'] = d.score
                cur['evidence'] = d.explain()
    for inc in out:
        inc['rules'] = dict(inc['rules'].most_common())
        inc['targets'] = [t for t, _ in inc['targets'].most_common(3)]
    out.sort(key=lambda i: (-i['peak_score'], -i['seconds']))
    return out


def analyze(path, rule_set=None, truth=None, tz=None, top=10):
    """One pass: traffic statistics, and detections if `rule_set` is given. Returns a result dict."""
    from nids.engine import RuleEngine
    an = Analyzer(rule_set.settings.home_net if rule_set else ('192.168.0.0/16',))
    dets = []
    eng = RuleEngine(rule_set, on_detection=dets.append) if rule_set else None
    t0 = time.time()
    for rec in pr.iter_any(path):
        an.add(rec)
        if eng is not None and rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    if eng is not None:
        eng.flush()
    elapsed = time.time() - t0
    bucket, tl = an.timeline()
    res = {'capture': os.path.basename(path), 'analysed_in_s': elapsed, 'summary': an.summary(top),
           'timeline_bucket_s': bucket, 'timeline': tl, 'detections': dets,
           'incidents': group_incidents(dets) if eng else [],
           'rules': [{'id': r.id, 'name': r.name, 'kind': r.kind, 'scope': r.scope, 'measure': r.measure,
                      'threshold': r.threshold_text(), 'weight': r.weight} for r in rule_set.rules] if rule_set else [],
           'truth': truth, 'tz': tz}
    fired = Counter(h.rule_id for d in dets for h in d.hits)
    res['rule_counts'] = dict(fired)
    return res


# ------------------------------------------------------------------------------------------- figures
def _style(ax):
    ax.set_facecolor(SURFACE)
    for side in ('top', 'right', 'left'):
        ax.spines[side].set_visible(False)
    ax.spines['bottom'].set_color(AXIS)
    ax.tick_params(colors=MUTED, labelcolor=INK2, length=0, labelsize=9)
    ax.grid(axis='y', color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _fmt_time(t, tz, seconds=False):
    return datetime.datetime.fromtimestamp(t, tz).strftime('%H:%M:%S' if seconds else '%H:%M')  # tz None = local time


def fig_timeline(res, path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter, MaxNLocator
    tz = res['tz']
    tl = res['timeline']
    xs = [t for t, _ in tl]
    short = bool(xs) and xs[-1] - xs[0] < 3600
    rules = [r for r in (res['rules'] or []) if res['rule_counts'].get(r['id'])]
    lanes = len(rules)
    fig = plt.figure(figsize=(11, 4.2 + 0.28 * lanes), facecolor=SURFACE)
    gs = fig.add_gridspec(2 if lanes else 1, 1, height_ratios=[3.2, 0.3 * lanes + 0.3] if lanes else [1], hspace=0.08)
    ax = fig.add_subplot(gs[0])
    _style(ax)
    for w in (res['truth'] or {}).get('windows', []):
        ax.axvspan(w['start'], w['end'], color=WINDOW_FILL, alpha=0.10, lw=0)
        ax.text((w['start'] + w['end']) / 2, 1.0, w['name'], transform=ax.get_xaxis_transform(), ha='center',
                va='bottom', fontsize=8.5, color=INK2)
    for i, name in enumerate(('TCP', 'UDP', 'ICMP')):
        ys = [r[i] for _, r in tl]
        if max(ys, default=0) > 0:
            ax.plot(xs, ys, color=SERIES[i], lw=1.6, solid_joinstyle='round', solid_capstyle='round', label=name)
    ax.set_ylabel(f'packets / s (mean per {res["timeline_bucket_s"]} s)', color=INK2, fontsize=9)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v / 1000:g}K' if v >= 1000 else f'{v:g}'))
    ax.legend(loc='lower left', bbox_to_anchor=(0, 1.0), frameon=False, fontsize=9, labelcolor=INK2, ncols=3, borderaxespad=0.2)
    ax.margins(x=0)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: _fmt_time(v, tz, short)))
    if xs and xs[-1] - xs[0] > 2 * 3600:  # ticks on whole hours of the display time zone
        d0 = datetime.datetime.fromtimestamp(xs[0], tz) if tz else datetime.datetime.fromtimestamp(xs[0]).astimezone()
        off = d0.utcoffset().total_seconds()
        first = (int(xs[0] + off) // 3600 + 1) * 3600 - off
        ax.set_xticks([first + 3600 * i for i in range(int((xs[-1] - first) // 3600) + 1)])
    else:
        ax.xaxis.set_major_locator(MaxNLocator(10))
    if lanes:
        ax.tick_params(labelbottom=False)
        lx = fig.add_subplot(gs[1], sharex=ax)
        lx.set_facecolor(SURFACE)
        for side in ('top', 'right', 'left'):
            lx.spines[side].set_visible(False)
        lx.spines['bottom'].set_color(AXIS)
        lx.tick_params(colors=MUTED, labelcolor=INK2, length=0, labelsize=8.5)
        per_rule = defaultdict(list)
        for d in res['detections']:
            for h in d.hits:
                per_rule[h.rule_id].append(d.time)
        for i, r in enumerate(rules):
            lx.eventplot([per_rule[r['id']]], lineoffsets=lanes - 1 - i, linelengths=0.6, linewidths=1.0, colors=INK2)
        lx.set_yticks(range(lanes))
        lx.set_yticklabels([r['id'] for r in reversed(rules)])
        lx.set_ylim(-0.6, lanes - 0.4)
        lx.set_title('detections per rule', loc='left', fontsize=9, color=INK2, pad=3)
        lx.xaxis.set_major_formatter(FuncFormatter(lambda v, _: _fmt_time(v, tz, short)))
    fig.savefig(path, dpi=150, bbox_inches='tight', facecolor=SURFACE)
    plt.close(fig)


def fig_bars(labels, values, path, title, highlight=None, legend=None, value_fmt=None):
    """Horizontal bars, largest on top. highlight: set of labels drawn in the accent (with a legend)."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    n = len(labels)
    fig, ax = plt.subplots(figsize=(6.4, 0.34 * n + 0.9), facecolor=SURFACE)
    _style(ax)
    ax.grid(axis='y', visible=False)
    ax.grid(axis='x', color=GRID, linewidth=0.8)
    ys = list(range(n))[::-1]
    colors = [ACCENT if (highlight is None or l in highlight) else NEUTRAL_BAR for l in labels]
    ax.barh(ys, values, height=0.55, color=colors)
    ax.set_yticks(ys)
    ax.set_yticklabels(labels, fontsize=9, color=INK)
    fmt = value_fmt or (lambda v: f'{v:,.0f}')
    vmax = max(values, default=1) or 1
    for y, v in zip(ys, values):
        ax.text(v + vmax * 0.01, y, fmt(v), va='center', fontsize=8.5, color=INK2)
    ax.set_xlim(0, vmax * 1.15)
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v / 1e6:g}M' if v >= 1e6 else f'{v / 1e3:g}K' if v >= 1e3 else f'{v:g}'))
    ax.set_title(title, loc='left', fontsize=10, color=INK)
    if highlight is not None and legend:
        ax.legend(handles=[Patch(color=ACCENT, label=legend[0]), Patch(color=NEUTRAL_BAR, label=legend[1])],
                  frameon=False, fontsize=8.5, labelcolor=INK2, loc='lower right')
    fig.savefig(path, dpi=150, bbox_inches='tight', facecolor=SURFACE)
    plt.close(fig)


# ------------------------------------------------------------------------------------------- report
def _img(path):
    with open(path, 'rb') as f:
        return 'data:image/png;base64,' + base64.b64encode(f.read()).decode()


def _table(rows, cols, fmt=None):
    fmt = fmt or {}
    h = ''.join(f'<th>{html.escape(c)}</th>' for c in cols)
    body = ''
    for r in rows:
        cells = []
        for c in cols:
            v = r.get(c, '')
            v = fmt[c](v) if c in fmt else (f'{v:,}' if isinstance(v, int) and not isinstance(v, bool) else v)
            cls = ' class="num"' if isinstance(r.get(c), (int, float)) and not isinstance(r.get(c), bool) else ''
            cells.append(f'<td{cls}>{html.escape(str(v))}</td>')
        body += '<tr>' + ''.join(cells) + '</tr>'
    return f'<div class="tw"><table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table></div>'


def _human_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


def write_report(res, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    s = res['summary']
    tz = res['tz']
    flagged = {i['src'] for i in res['incidents']}
    figs = {}
    figs['timeline'] = os.path.join(out_dir, 'fig_timeline.png')
    fig_timeline(res, figs['timeline'])
    figs['protocols'] = os.path.join(out_dir, 'fig_protocols.png')
    fig_bars([p['protocol'] for p in s['protocols']], [p['packets'] for p in s['protocols']], figs['protocols'], 'Packets by protocol')
    figs['talkers'] = os.path.join(out_dir, 'fig_top_sources.png')
    fig_bars([t['ip'] for t in s['top_sources']], [t['packets'] for t in s['top_sources']], figs['talkers'],
             'Top talkers (packets sent)', highlight=flagged, legend=('triggered a rule', 'no detection'))
    figs['services'] = os.path.join(out_dir, 'fig_services.png')
    fig_bars([t['service'] for t in s['top_services']], [t['packets'] for t in s['top_services']], figs['services'], 'Top services (packets)')
    if res['rule_counts']:
        rc = sorted(res['rule_counts'].items(), key=lambda kv: -kv[1])
        figs['rules'] = os.path.join(out_dir, 'fig_rules.png')
        fig_bars([k for k, _ in rc], [v for _, v in rc], figs['rules'], 'Detections per rule (source-seconds)')

    dets = res['detections']
    with open(os.path.join(out_dir, 'detections.jsonl'), 'w') as f:
        for d in dets:
            f.write(json.dumps(d.to_dict()) + '\n')
    with open(os.path.join(out_dir, 'incidents.json'), 'w') as f:
        json.dump(res['incidents'], f, indent=1)
    with open(os.path.join(out_dir, 'summary.json'), 'w') as f:
        json.dump({k: v for k, v in res.items() if k not in ('detections', 'timeline')} | {'detections': len(dets)}, f, indent=1, default=str)

    t = lambda x: datetime.datetime.fromtimestamp(x, tz).strftime('%Y-%m-%d %H:%M:%S') if x else '-'
    hm = lambda x: datetime.datetime.fromtimestamp(x, tz).strftime('%H:%M:%S')
    tiles = [('Packets', f"{s['packets']:,}"), ('Traffic', _human_bytes(s['bytes'])),
             ('Duration', f"{s['duration_s'] / 3600:.2f} h" if s['duration_s'] >= 3600 else f"{s['duration_s']:.0f} s"),
             ('Hosts', f"{s['hosts']:,}"), ('Peak rate', f"{s['peak_pps']:,} pkt/s"),
             ('Incidents', f"{len(res['incidents'])}" if res['rules'] else 'rules off')]
    tile_html = ''.join(f'<div class="tile"><div class="lab">{a}</div><div class="val">{b}</div></div>' for a, b in tiles)
    inc_rows = [{'source': i['src'], 'start': hm(i['start']), 'end': hm(i['end']),
                 'alert seconds': i['seconds'], 'peak score': f"{i['peak_score']:g}",
                 'rules (seconds fired)': ', '.join(f'{k} ({v})' for k, v in i['rules'].items()),
                 'targets': ', '.join(i['targets']) or '-'} for i in res['incidents'][:25]]
    evidence = ''.join(f'<li><code>{html.escape(i["src"])}</code> at peak: {html.escape(i["evidence"])}</li>'
                       for i in res['incidents'][:8])
    rule_rows = [{'rule': r['id'], 'kind': r['kind'], 'per': r['scope'], 'alert when': f"{r['measure']} {r['threshold']}",
                  'weight': f"{r['weight']:g}", 'fired (source-seconds)': res['rule_counts'].get(r['id'], 0)} for r in res['rules']]
    truth_note = ''
    if res['truth']:
        truth_note = '<p class="note">Shaded bands: attack windows from the dataset ground truth (' + \
                     html.escape(', '.join(w['name'] for w in res['truth']['windows'])) + ').</p>'
    tl_rows = [{'time': hm(tt), 'TCP pkt/s': round(r[0], 1), 'UDP pkt/s': round(r[1], 1), 'ICMP pkt/s': round(r[2], 1)}
               for tt, r in res['timeline']]
    sections = [
        f'<section><h2>Timeline</h2><img src="{_img(figs["timeline"])}" alt="Packets per second by protocol over time, with detections per rule underneath">{truth_note}'
        f'<details><summary>Timeline as a table ({len(tl_rows)} rows)</summary>{_table(tl_rows, list(tl_rows[0]) if tl_rows else [])}</details></section>',
    ]
    if res['rules']:
        sections.append('<section><h2>Incidents</h2><p class="note">Detections of one source less than '
                        f'{INCIDENT_GAP:.0f} s apart form one incident. The score of a second is the sum of the weights of the rules '
                        'that fired for that source; the evidence lists every point.</p>'
                        + (_table(inc_rows, list(inc_rows[0])) if inc_rows else '<p>No detections.</p>')
                        + (f'<h3>Evidence (peak second of each incident)</h3><ul class="ev">{evidence}</ul>' if evidence else '')
                        + '</section>')
        sections.append('<section><h2>Rules</h2>' + _table(rule_rows, list(rule_rows[0])) +
                        (f'<img src="{_img(figs["rules"])}" alt="Detections per rule">' if 'rules' in figs else '') + '</section>')
    sections.append('<section class="grid2"><div><h2>Protocols</h2>'
                    f'<img src="{_img(figs["protocols"])}" alt="Packets by protocol">'
                    + _table([{'protocol': p['protocol'], 'packets': p['packets'], 'bytes': _human_bytes(p['bytes'])} for p in s['protocols']], ['protocol', 'packets', 'bytes'])
                    + '<h3>TCP flags</h3>' + _table(s['tcp_flags'], ['flags', 'packets'])
                    + '<h3>Direction</h3>' + _table(s['direction'], ['direction', 'packets']) + '</div>'
                    '<div><h2>Top talkers</h2>'
                    f'<img src="{_img(figs["talkers"])}" alt="Top talkers by packets sent">'
                    + _table([{'source': x['ip'], 'packets': x['packets'], 'bytes': _human_bytes(x['bytes']),
                               'network': 'home' if x['home'] else 'external'} for x in s['top_sources']], ['source', 'packets', 'bytes', 'network'])
                    + '</div></section>')
    sections.append('<section class="grid2"><div><h2>Services</h2>'
                    f'<img src="{_img(figs["services"])}" alt="Top services">'
                    + _table(s['top_services'], ['service', 'port', 'packets']) + '</div>'
                    '<div><h2>Top conversations</h2>' + _table(s['top_conversations'], ['src', 'dst', 'packets'])
                    + '<h2>Top destinations</h2>' + _table([{'destination': x['ip'], 'packets': x['packets'],
                                                             'network': 'home' if x['home'] else 'external'} for x in s['top_destinations']],
                                                           ['destination', 'packets', 'network']) + '</div></section>')
    page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Traffic Analysis Report</title><style>
:root{{--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--line:#e1e0d9;--ring:rgba(11,11,11,.10);color-scheme:light}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--line:#2c2c2a;--ring:rgba(255,255,255,.10);color-scheme:dark}}}}
:root[data-theme="dark"]{{--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--line:#2c2c2a;--ring:rgba(255,255,255,.10);color-scheme:dark}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:24px 16px 64px}}h1{{font-size:26px;margin:0 0 4px}}h2{{font-size:18px;margin:0 0 10px}}h3{{font-size:14px;margin:18px 0 6px;color:var(--ink2)}}
.sub{{color:var(--ink2);margin:0 0 20px}}section{{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:18px;margin:16px 0}}
img{{max-width:100%;height:auto;display:block;background:#fcfcfb;border-radius:6px}}.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
.tile{{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:12px 14px}}.lab{{color:var(--ink2);font-size:13px}}.val{{font-size:22px;font-weight:600}}
.tw{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}}th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);white-space:nowrap}}
th{{color:var(--ink2);font-weight:600}}td.num{{text-align:right;font-variant-numeric:tabular-nums}}.note{{color:var(--ink2);font-size:13px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}@media (max-width:820px){{.grid2{{grid-template-columns:1fr}}}}
.ev{{font-size:13px;color:var(--ink2);padding-left:18px}}.ev li{{margin:4px 0;word-break:break-word}}code{{font-size:12.5px}}details{{margin-top:10px;font-size:13px}}
</style></head><body><main>
<h1>Traffic Analysis Report</h1>
<p class="sub">{html.escape(res["capture"])} &middot; {t(s["first"])} to {t(s["last"])}{" (" + str(tz) + ")" if tz else ""} &middot; analysed in {res["analysed_in_s"]:.0f} s</p>
<div class="tiles">{tile_html}</div>
{"".join(sections)}
</main></body></html>'''
    with open(os.path.join(out_dir, 'report.html'), 'w') as f:
        f.write(page)
    return os.path.join(out_dir, 'report.html')


def print_summary(res, max_incidents=10):
    s = res['summary']
    tz = res['tz']
    hm = lambda x: datetime.datetime.fromtimestamp(x, tz).strftime('%H:%M:%S')
    print(f"\n{res['capture']}: {s['packets']:,} packets, {_human_bytes(s['bytes'])}, {s['duration_s']:.0f} s, "
          f"{s['hosts']:,} hosts, peak {s['peak_pps']:,} pkt/s")
    print('  protocols: ' + ', '.join(f"{p['protocol']} {p['packets'] / max(1, s['packets']):.1%}" for p in s['protocols'][:4]))
    print('  top talkers: ' + ', '.join(f"{t['ip']} ({t['packets']:,})" for t in s['top_sources'][:5]))
    print('  top services: ' + ', '.join(f"{t['service']} ({t['packets']:,})" for t in s['top_services'][:6]))
    if res['rules']:
        print(f"  detections: {len(res['detections']):,} source-seconds in {len(res['incidents'])} incidents")
        for i in res['incidents'][:max_incidents]:
            print(f"    {i['src']:<16} {hm(i['start'])}-{hm(i['end'])}  {i['seconds']:>5} s  peak score {i['peak_score']:g}  "
                  + ', '.join(f'{k}({v})' for k, v in i['rules'].items()))
