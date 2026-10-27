"""
Rule engine driven by a rule file (rules.yaml, loaded by rule_set.py).

The engine implements the built-in measures; the rule file decides which measures are used, for whom
(source or protected victim), with which threshold and whether that threshold is fixed or adaptive.
Every window (1 s by default) it measures, checks each rule, and reports one Detection per source that
triggered at least one rule. A Detection carries a transparent score (sum of the weights of the rules
that fired) and the evidence for every point of it.

    from nids.rule_set import load_rules
    from nids.engine import RuleEngine
    eng = RuleEngine(load_rules('config/rules.yaml'), on_detection=print)
    for features in packets:            # dicts as produced by packet_parser.parse_packet()
        eng.process_packet(features)
    eng.flush()

Semantics follow AdaptiveRuleEngine (same windows, EMA, freeze, decay and pruning) so that a rule file
with the same settings reproduces its results; see test_engine.py.
"""
import ipaddress
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field

RATIO_MEASURES = {'half_open_ratio', 'port_entropy'}
SLIDING_MEASURES = {'syn_rate', 'icmp_rate', 'distinct_ports', 'victim_pps', 'victim_conn_rate'}


class SlidingCounts:
    """Events of the last `span` seconds, counted per key and, optionally, per sub-key (port, or sender).
    Used by count rules whose window_seconds is longer than the engine window."""

    def __init__(self, span):
        self.span = span
        self.events = deque()                             # (time, key, sub)
        self.n = defaultdict(int)                         # key -> events
        self.sub = defaultdict(lambda: defaultdict(int))  # key -> sub-key -> events

    def add(self, t, key, sub=None):
        self.events.append((t, key, sub))
        self.n[key] += 1
        if sub is not None:
            self.sub[key][sub] += 1

    def expire(self, cut):
        """Forget events before `cut`."""
        ev, n, sub = self.events, self.n, self.sub
        while ev and ev[0][0] < cut:
            _, key, s = ev.popleft()
            n[key] -= 1
            if not n[key]:
                del n[key]
            if s is not None:
                d = sub[key]
                d[s] -= 1
                if not d[s]:
                    del d[s]
                    if not d:
                        del sub[key]


@dataclass
class Hit:
    """One rule firing for one host in one window."""
    rule_id: str
    rule_name: str
    kind: str
    measure: str
    value: float
    threshold: float
    op: str
    policy: str
    baseline: float      # EMA baseline (adaptive) or None (fixed)
    weight: float
    target: str = None   # protected host, for victim-scope rules

    def explain(self):
        v = f'{self.value:.2f}' if self.measure in RATIO_MEASURES else f'{self.value:g}'
        th = f'{self.threshold:.2f}' if self.measure in RATIO_MEASURES else f'{self.threshold:g}'
        s = f'{self.rule_id}(+{self.weight:g}): {self.measure} {v} {self.op} {th} [{self.policy}'
        if self.baseline is not None:
            s += f', baseline {self.baseline:.1f}'
        s += ']'
        if self.target:
            s += f' to {self.target}'
        return s

    def to_dict(self):
        return dict(self.__dict__)


@dataclass
class Detection:
    """All rules that fired for one source in one window, and the resulting score."""
    time: float          # start of the window
    src: str
    score: float
    hits: list = field(default_factory=list)

    @property
    def rule_ids(self):
        return sorted({h.rule_id for h in self.hits})

    def explain(self):
        return f'score {self.score:g} = ' + ' + '.join(h.explain() for h in self.hits)

    def to_dict(self):
        return {'time': self.time, 'src': self.src, 'score': self.score, 'rules': self.rule_ids,
                'hits': [h.to_dict() for h in self.hits]}


def home_matcher(nets):
    """Fast membership test for a list of CIDRs on dotted-quad strings ([] = everything is home)."""
    if not nets:
        return lambda ip: True
    prefixes, exact, other = [], set(), []
    for n in nets:
        net = ipaddress.ip_network(n, strict=False)
        if net.version == 4 and net.prefixlen == 0:
            return lambda ip: True
        if net.version == 4 and net.prefixlen == 32:
            exact.add(str(net.network_address))
        elif net.version == 4 and net.prefixlen in (8, 16, 24):
            prefixes.append('.'.join(str(net.network_address).split('.')[:net.prefixlen // 8]) + '.')
        else:
            other.append(net)
    prefixes = tuple(prefixes)
    if not other:
        return lambda ip: ip in exact or ip.startswith(prefixes)

    def match(ip):
        if ip in exact or ip.startswith(prefixes):
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in other)
    return match


class RuleEngine:
    PROBE_REPLY_SECONDS = 5.0  # an ICMP unreachable must follow the rejected datagram within this time

    def __init__(self, rule_set, on_detection=None):
        self.rule_set = rule_set
        self.rules = list(rule_set.rules)
        st = rule_set.settings
        self.window = st.window_seconds
        self.timeout = st.connection_timeout_seconds
        self.is_home = home_matcher(st.home_net)
        self.on_detection = on_detection or (lambda d: None)
        need = {r.measure for r in self.rules}
        self.need_syn = 'syn_rate' in need
        self.need_icmp = 'icmp_rate' in need
        self.need_ports = 'distinct_ports' in need
        self.need_entropy = 'port_entropy' in need
        self.need_half_open = 'half_open_ratio' in need
        self.need_rejected = 'rejected_probes' in need
        self.need_victim = bool(need & {'victim_pps', 'victim_conn_rate'})
        par = {r.measure: r.params for r in self.rules}
        self.port_decay = float(par.get('port_entropy', {}).get('decay', 0.5))
        rp = par.get('rejected_probes', {})
        rp_window = {r.measure: r.window_seconds for r in self.rules}.get('rejected_probes')
        self.reject_window = float(rp_window if rp_window is not None else rp.get('window_seconds', 60.0))
        # count rules with window_seconds longer than the engine window are measured over the last W seconds
        # (events in [t_end - W, t_end), the anchor rejected_probes uses); all others use the per-window counters
        self.span = {r.id: r.window_seconds for r in self.rules
                     if r.measure in SLIDING_MEASURES and r.window_seconds is not None and r.window_seconds > self.window}
        self.slide = {}  # W -> measure -> SlidingCounts
        for r in self.rules:
            if r.id in self.span:
                sl = self.slide.setdefault(r.window_seconds, {})
                ms = {'victim_pps', 'victim_conn_rate'} if r.scope == 'victim' else {r.measure}
                for m in ms:
                    sl.setdefault(m, SlidingCounts(r.window_seconds))
        self.reject_inbound_only = rp.get('direction', 'inbound') == 'inbound'

        self.window_start = 0.0
        self.latest_time = 0.0
        # per-window counters
        self.syn = defaultdict(int)
        self.icmp = defaultdict(int)
        self.ports_win = defaultdict(set)
        self.victim_pkts = defaultdict(int)
        self.victim_syns = defaultdict(int)
        self.victim_srcs = defaultdict(lambda: defaultdict(int))
        # state that outlives a window
        self.port_freq = defaultdict(lambda: defaultdict(float))  # src -> port -> decayed count
        self.conns = {}                                         # (src, dst, sport, dport) -> handshake completed?
        self.conn_ts = {}
        self.src_conns = defaultdict(set)
        self.syn_seen = {}       # inbound (initiator, responder, isport, rport) -> ts of the SYN
        self.probe_seen = {}     # inbound (initiator, responder) -> ts of the last non-TCP datagram
        self.reject_times = defaultdict(deque)  # initiator -> times its probes were rejected (last reject_window s)
        # adaptive thresholds, per rule
        self.baseline = {r.id: defaultdict(float) for r in self.rules}
        self.frozen_until = {r.id: {} for r in self.rules}
        self.packets = 0
        self.detections = 0

    # ------------------------------------------------------------------ packets
    def process_packet(self, f):
        t = f['timestamp']
        if t - self.window_start >= self.window:
            self.latest_time = t
            self._rollover()
            self.window_start = t
        self.packets += 1
        src = f['src_ip']
        dst = f['dst_ip']
        proto = f['protocol']

        if proto == 6:
            flags = f['tcp_flags'] or ''
            sport = f['src_port']
            dport = f['dst_port']
            syn_only = 'S' in flags and 'A' not in flags
            if self.need_victim and self.is_home(dst):
                if dport is not None and dport < 1024:
                    self.victim_pkts[dst] += 1
                    self.victim_srcs[dst][src] += 1
                if syn_only:
                    self.victim_syns[dst] += 1
            if syn_only:
                if self.need_syn:
                    self.syn[src] += 1
                if dport is not None:
                    if self.need_ports:
                        self.ports_win[src].add(dport)
                    if self.need_entropy:
                        self.port_freq[src][dport] += 1
                    if self.need_half_open and sport is not None:
                        c = (src, dst, sport, dport)
                        if c not in self.conns:
                            self.conns[c] = False
                            self.conn_ts[c] = t
                            self.src_conns[src].add(c)
                    if self.need_rejected and (not self.reject_inbound_only or (self.is_home(dst) and not self.is_home(src))):
                        self.syn_seen[(src, dst, sport, dport)] = t
            elif 'A' in flags and self.need_half_open and dport is not None and sport is not None:
                c = (src, dst, sport, dport)
                if c in self.conns:
                    self.conns[c] = True
                    self.conn_ts[c] = t
            if self.need_rejected and 'R' in flags:
                st = self.syn_seen.pop((dst, src, dport, sport), None)
                if st is not None and t - st <= self.timeout:
                    self._credit_rejection(dst, t)
        elif proto == 1:
            if self.need_icmp:
                self.icmp[src] += 1
            if self.need_rejected and f.get('icmp_type', 3) == 3:
                st = self.probe_seen.get((dst, src))
                if st is not None and t - st <= self.PROBE_REPLY_SECONDS:
                    self._credit_rejection(dst, t)
        else:
            if self.need_victim and proto == 17 and self.is_home(dst):
                dport = f['dst_port']
                if dport is not None and dport < 1024:
                    self.victim_pkts[dst] += 1
                    self.victim_srcs[dst][src] += 1
            if self.need_rejected and (not self.reject_inbound_only or (self.is_home(dst) and not self.is_home(src))):
                self.probe_seen[(src, dst)] = t
        if self.slide:
            self._slide_add(f, t, src, dst, proto)

    def _slide_add(self, f, t, src, dst, proto):
        """Same events as the per-window counters above, fed to the sliding counters."""
        dport = f['dst_port']
        syn_only = False
        if proto == 6:
            flags = f['tcp_flags'] or ''
            syn_only = 'S' in flags and 'A' not in flags
        service = proto in (6, 17) and dport is not None and dport < 1024
        home = None
        for sl in self.slide.values():
            if syn_only:
                if 'syn_rate' in sl:
                    sl['syn_rate'].add(t, src)
                if 'distinct_ports' in sl and dport is not None:
                    sl['distinct_ports'].add(t, src, dport)
            elif proto == 1 and 'icmp_rate' in sl:
                sl['icmp_rate'].add(t, src)
            if 'victim_pps' in sl and (service or syn_only):
                if home is None:
                    home = self.is_home(dst)
                if home:
                    if service:
                        sl['victim_pps'].add(t, dst, src)
                    if syn_only:
                        sl['victim_conn_rate'].add(t, dst)

    def _credit_rejection(self, who, t):
        self.reject_times[who].append(t)

    # ------------------------------------------------------------------ measures
    def _measure(self, rule):
        """{key: value} for this window; key = source (source scope) or victim (victim scope)."""
        m = rule.measure
        span = self.span.get(rule.id)
        if span:
            sl = self.slide[span]
            for c in sl.values():
                c.expire(self.latest_time - span)
            if m in ('syn_rate', 'icmp_rate'):
                return dict(sl[m].n)
            if m == 'distinct_ports':
                return {s: len(p) for s, p in sl[m].sub.items()}
            counts = sl[m].n
            return {d: counts.get(d, 0) for d in set(sl['victim_pps'].n) | set(sl['victim_conn_rate'].n)}
        if m == 'syn_rate':
            return self.syn
        if m == 'icmp_rate':
            return self.icmp
        if m == 'distinct_ports':
            return {s: len(p) for s, p in self.ports_win.items()}
        if m == 'port_entropy':
            out = {}
            for s, pc in self.port_freq.items():
                if len(pc) >= rule.min_support:
                    total = sum(pc.values())
                    out[s] = -sum((c / total) * math.log2(c / total) for c in pc.values())
            return out
        if m == 'half_open_ratio':
            out = {}
            for s, cs in self.src_conns.items():
                if len(cs) >= max(1, rule.min_support):
                    out[s] = sum(1 for c in cs if not self.conns[c]) / len(cs)
            return out
        if m == 'rejected_probes':
            cut = self.latest_time - self.reject_window
            out = {}
            for s, q in self.reject_times.items():
                while q and q[0] < cut:
                    q.popleft()
                if q:
                    out[s] = len(q)
            return out
        if m in ('victim_pps', 'victim_conn_rate'):
            counts = self.victim_pkts if m == 'victim_pps' else self.victim_syns
            return {d: counts.get(d, 0) for d in set(self.victim_pkts) | set(self.victim_syns)}
        raise ValueError(m)

    def _check(self, rule, key, value):
        """(alerted, threshold, baseline) and the adaptive baseline update (with freeze)."""
        if rule.policy == 'fixed':
            thr, base = rule.value, None
        else:
            store = self.baseline[rule.id]
            base = store[key]
            thr = max(rule.value, rule.multiplier * base)
        alerted = value > thr if rule.op == '>' else value >= thr
        if rule.policy == 'adaptive':
            now = self.window_start
            frozen = self.frozen_until[rule.id]
            if alerted:
                frozen[key] = now + rule.freeze_seconds
            elif now >= frozen.get(key, 0):
                store[key] = rule.alpha * value + (1 - rule.alpha) * base
        return alerted, thr, base

    def _attribute(self, victim, span=None):
        srcs = self.slide[span]['victim_pps'].sub.get(victim) if span else self.victim_srcs.get(victim)
        if srcs:
            return max(srcs, key=srcs.get)
        return 'multiple'

    def _rollover(self):
        now = self.window_start
        by_src = defaultdict(list)
        for rule in self.rules:
            values = self._measure(rule)
            for key, value in values.items():
                alerted, thr, base = self._check(rule, key, value)
                if not alerted:
                    continue
                if rule.scope == 'victim':
                    src, target = self._attribute(key, self.span.get(rule.id)), key
                else:
                    src, target = key, None
                by_src[src].append(Hit(rule.id, rule.name, rule.kind, rule.measure, value, thr, rule.op,
                                       rule.policy, base, rule.weight, target))
            if rule.policy == 'adaptive':
                store, frozen = self.baseline[rule.id], self.frozen_until[rule.id]
                for k in [k for k, v in store.items() if v < 0.01 and k not in values and now >= frozen.get(k, 0)]:
                    del store[k]
        for src, hits in sorted(by_src.items(), key=lambda kv: -len(kv[1])):
            score = sum({h.rule_id: h.weight for h in hits}.values())
            self.detections += 1
            self.on_detection(Detection(now, src, score, hits))
        self._end_window()

    def _end_window(self):
        self.syn.clear()
        self.icmp.clear()
        self.ports_win.clear()
        self.victim_pkts.clear()
        self.victim_syns.clear()
        self.victim_srcs.clear()
        if self.port_freq:
            elapsed = max(1, int((self.latest_time - self.window_start) / self.window))
            decay = self.port_decay ** min(elapsed, 64)
            for s in list(self.port_freq):
                pc = self.port_freq[s]
                for p in list(pc):
                    pc[p] *= decay
                    if pc[p] < 0.5:
                        del pc[p]
                if not pc:
                    del self.port_freq[s]
        now = max(self.window_start, self.latest_time)
        if self.conn_ts:
            for c in [c for c, ts in self.conn_ts.items() if now - ts > self.timeout]:
                del self.conns[c]
                del self.conn_ts[c]
                s = self.src_conns.get(c[0])
                if s is not None:
                    s.discard(c)
                    if not s:
                        del self.src_conns[c[0]]
        if self.syn_seen:
            for k in [k for k, ts in self.syn_seen.items() if now - ts > self.timeout]:
                del self.syn_seen[k]
        if self.probe_seen:
            for k in [k for k, ts in self.probe_seen.items() if now - ts > self.PROBE_REPLY_SECONDS]:
                del self.probe_seen[k]
        if self.reject_times:
            cut = now - self.reject_window
            for s in [s for s, q in self.reject_times.items() if not q or q[-1] < cut]:
                del self.reject_times[s]

    def flush(self):
        """Evaluate the last (partial) window when the capture ends."""
        self._rollover()
