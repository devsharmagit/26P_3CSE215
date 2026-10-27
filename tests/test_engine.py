"""
Tests for the rule-file engine: rule file validation, measures, threshold policies, score/evidence,
legacy equivalence, the classic-pcap reader and incident grouping.
Run (from the repository root):  python -m pytest -q
"""
import os

import pytest

from legacy import adaptive_engine
from nids import analyzer
from nids import pcapng_reader as pr
from legacy.adaptive_engine import AdaptiveRuleEngine
from nids.engine import RuleEngine, home_matcher
from nids.rule_set import RuleFileError, load_rules, parse_rules

from nids.paths import LEGACY_RULES, RULES, SYNTHETIC_PCAP as SYNTHETIC


def pkt(ts, src, dst, sport, dport, flags='S', proto=6, **extra):
    f = {'timestamp': ts, 'src_ip': src, 'dst_ip': dst, 'protocol': proto,
         'src_port': sport if proto in (6, 17) else None, 'dst_port': dport if proto in (6, 17) else None,
         'tcp_flags': flags if proto == 6 else None, 'length': 60}
    f.update(extra)
    return f


def one_rule(measure, value, policy='fixed', **kw):
    rule = {'id': 'r', 'measure': measure, 'threshold': {'policy': policy, 'value': value, **kw.pop('threshold', {})}}
    rule.update(kw)
    return parse_rules({'settings': {'home_net': ['192.168.0.0/16']}, 'rules': [rule]})


def run(rs, packets):
    dets = []
    eng = RuleEngine(rs, on_detection=dets.append)
    for p in packets:
        eng.process_packet(p)
    eng.flush()
    return dets


# ---------------------------------------------------------------- rule file
def test_default_rule_file_loads():
    rs = load_rules(RULES)
    ids = [r.id for r in rs.rules]
    assert len(ids) == len(set(ids)) >= 8
    assert {r.kind for r in rs.rules} == {'count', 'behaviour'}


@pytest.mark.parametrize('rule, msg', [
    ({'id': 'x', 'measure': 'nope', 'threshold': {'value': 1}}, 'unknown measure'),
    ({'id': 'x', 'measure': 'syn_rate', 'threshold': {'value': 1, 'policy': 'magic'}}, 'policy'),
    ({'id': 'x', 'measure': 'syn_rate', 'scope': 'victim', 'threshold': {'value': 1}}, 'cannot have scope'),
    ({'id': 'x', 'measure': 'syn_rate'}, 'missing threshold'),
])
def test_rule_file_errors(rule, msg):
    with pytest.raises(RuleFileError, match=msg):
        parse_rules({'rules': [rule]})


def test_duplicate_ids_rejected():
    r = {'id': 'x', 'measure': 'syn_rate', 'threshold': {'value': 1}}
    with pytest.raises(RuleFileError, match='duplicate'):
        parse_rules({'rules': [r, dict(r)]})


def test_variant_forces_policy_and_filters_kind():
    rs = load_rules(RULES)
    v = rs.variant(policy='adaptive', kinds=['behaviour'])
    assert v.rules and all(r.kind == 'behaviour' and r.policy == 'adaptive' for r in v.rules)
    assert all(r.policy == 'fixed' for r in rs.rules)  # original untouched


def test_home_matcher():
    m = home_matcher(['192.168.0.0/16', '10.1.2.3/32', '172.16.0.0/12'])
    assert m('192.168.10.50') and m('10.1.2.3') and m('172.20.1.1')
    assert not m('10.1.2.4') and not m('8.8.8.8') and not m('172.32.0.1')
    assert home_matcher([])('8.8.8.8')


# ---------------------------------------------------------------- measures & policies
def test_fixed_syn_rate():
    flood = [pkt(1 + i / 1000, '10.0.0.9', '192.168.1.1', 1000 + i, 80) for i in range(150)]
    dets = run(one_rule('syn_rate', 100), flood)
    assert [(d.src, d.hits[0].value) for d in dets] == [('10.0.0.9', 150)]
    assert run(one_rule('syn_rate', 100), flood[:90]) == []


def test_adaptive_threshold_rises_for_a_busy_host_but_freezes_under_attack():
    rs = one_rule('syn_rate', 50, policy='adaptive', threshold={'multiplier': 2.0, 'alpha': 0.5, 'freeze_seconds': 60})
    syns = lambda t, n, port0=1000: [pkt(t + i / (n + 1), '10.0.0.9', '192.168.1.1', port0 + i, 80) for i in range(n)]
    # 40 SYN/s for 10 s (below the floor) teaches a baseline of ~40, so 70 SYN/s is then normal for this host
    normal = [p for t in range(1, 11) for p in syns(t, 40)] + [p for t in range(11, 21) for p in syns(t, 70)]
    assert run(rs, normal) == []
    assert run(one_rule('syn_rate', 50), normal)  # a fixed line of 50 flags the same host every second
    burst = [p for t in range(30, 40) for p in syns(t, 300, 5000)]
    dets = run(rs, normal + burst)
    assert sum(1 for d in dets if d.time >= 30) == 10  # every flood second: the frozen baseline does not absorb it
    # a host that is above the floor from its first second never gets a baseline (it is always frozen)
    assert len(run(rs, [p for t in range(1, 21) for p in syns(t, 60)])) == 20


def test_distinct_ports():
    scan = [pkt(1 + i / 100, '10.0.0.9', '192.168.1.1', 40000, 1 + i) for i in range(30)]
    assert [d.hits[0].value for d in run(one_rule('distinct_ports', 20), scan)] == [30]


def test_half_open_ratio():
    rs = one_rule('half_open_ratio', 0.8, threshold={'op': '>='}, min_support=20)
    half = [pkt(1 + i / 100, '10.0.0.9', '192.168.1.1', 1000 + i, 80) for i in range(25)]
    assert run(rs, half)
    done = half + [pkt(1.5 + i / 100, '10.0.0.9', '192.168.1.1', 1000 + i, 80, flags='A') for i in range(25)]
    assert run(rs, sorted(done, key=lambda p: p['timestamp'])) == []


def rejected_syns(n, src='203.0.113.7', dst='192.168.1.10', t0=1.0, gap=2.0):
    out = []
    for i in range(n):
        t = t0 + i * gap
        out.append(pkt(t, src, dst, 40000 + i, 1 + i))
        out.append(pkt(t + 0.01, dst, src, 1 + i, 40000 + i, flags='RA'))
    return out


def test_rejected_probes_counts_slow_inbound_rejections():
    rs = one_rule('rejected_probes', 10, params={'window_seconds': 60, 'direction': 'inbound'})
    dets = run(rs, rejected_syns(15))  # one probe every 2 s: far too slow for any per-second rule
    assert dets and all(d.src == '203.0.113.7' for d in dets)
    assert max(h.value for d in dets for h in d.hits) == 15


def test_rejected_probes_ignores_outbound_and_answered_probes():
    rs = one_rule('rejected_probes', 10, params={'window_seconds': 60, 'direction': 'inbound'})
    outbound = rejected_syns(15, src='192.168.1.20', dst='93.184.216.34')
    assert run(rs, outbound) == []
    answered = []
    for i in range(15):
        answered.append(pkt(1 + 2 * i, '203.0.113.7', '192.168.1.10', 40000 + i, 80))
        answered.append(pkt(1.01 + 2 * i, '192.168.1.10', '203.0.113.7', 80, 40000 + i, flags='SA'))
    assert run(rs, answered) == []


def test_rejected_probes_window_expires():
    rs = one_rule('rejected_probes', 10, params={'window_seconds': 60})
    probes = rejected_syns(15, gap=1.0)
    quiet = [pkt(200 + i, '192.168.1.30', '192.168.1.31', 5000, 53, proto=17) for i in range(5)]
    dets = run(rs, probes + quiet)
    assert dets and max(d.time for d in dets) < 80  # stops at most one window after the last rejection


def test_rejected_probes_udp_and_icmp_unreachable():
    rs = one_rule('rejected_probes', 10)
    pk = []
    for i in range(12):
        pk.append(pkt(1 + 2 * i, '203.0.113.7', '192.168.1.10', 50000, 100 + i, proto=17))
        pk.append(pkt(1.01 + 2 * i, '192.168.1.10', '203.0.113.7', None, None, proto=1, icmp_type=3, icmp_code=3))
    assert run(rs, pk)
    echo = [dict(p, icmp_type=0) if p['protocol'] == 1 else p for p in pk]  # echo replies are not rejections
    assert run(rs, echo) == []


def test_victim_rule_attributes_dominant_source():
    rs = one_rule('victim_conn_rate', 32)
    pk = [pkt(1 + i / 1000, '10.0.0.9' if i % 4 else '10.0.0.8', '192.168.1.1', 1000 + i, 80) for i in range(100)]
    (d,) = run(rs, pk)
    assert d.src == '10.0.0.9' and d.hits[0].target == '192.168.1.1'


def test_score_and_evidence():
    rs = parse_rules({'rules': [
        {'id': 'a', 'measure': 'syn_rate', 'threshold': {'value': 100}, 'weight': 2},
        {'id': 'b', 'measure': 'distinct_ports', 'threshold': {'value': 20}, 'weight': 1},
        {'id': 'c', 'measure': 'icmp_rate', 'threshold': {'value': 100}, 'weight': 5}]})
    scan = [pkt(1 + i / 1000, '10.0.0.9', '192.168.1.1', 40000, 1 + i) for i in range(150)]
    (d,) = run(rs, scan)
    assert d.score == 3 and d.rule_ids == ['a', 'b']
    text = d.explain()
    assert text.startswith('score 3 = ') and 'a(+2): syn_rate 150 > 100 [fixed]' in text and 'b(+1)' in text


# ---------------------------------------------------------------- legacy equivalence
@pytest.mark.skipif(not os.path.exists(SYNTHETIC), reason='synthetic pcap missing')
def test_engine_reproduces_legacy_adaptive_engine():
    names = {'Adaptive SYN Flood': 'syn_flood', 'Adaptive ICMP Flood': 'icmp_flood', 'Entropy Port Scan': 'port_entropy',
             'Half-Open DoS': 'half_open', 'Victim Packet Flood': 'victim_packet_flood', 'Victim Connection Flood': 'victim_conn_flood'}
    old = []
    orig = adaptive_engine.generate_alert
    adaptive_engine.generate_alert = lambda ts, rule, src, d: old.append((ts, names[rule], src))
    try:
        e = AdaptiveRuleEngine()
        for r in pr.iter_any(SYNTHETIC):
            if r[3] in (1, 6, 17):
                e.process_packet(pr.to_features(r[:7]))
        e.flush()
    finally:
        adaptive_engine.generate_alert = orig
    new = []
    eng = RuleEngine(load_rules(LEGACY_RULES),
                     on_detection=lambda d: new.extend((d.time, h.rule_id, d.src) for h in d.hits))
    for r in pr.iter_any(SYNTHETIC):
        if r[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(r[:7]))
    eng.flush()
    assert old and sorted(old) == sorted(new)


# ---------------------------------------------------------------- reader & analyzer
def test_classic_pcap_reader(tmp_path):
    from scapy.all import ICMP, IP, TCP, UDP, Ether, wrpcap
    pk = [Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=1234, dport=80, flags='S'),
          Ether() / IP(src='10.0.0.2', dst='10.0.0.1') / UDP(sport=53, dport=5000) / b'abcd',
          Ether() / IP(src='10.0.0.3', dst='10.0.0.1') / ICMP(type=3, code=3)]
    for i, p in enumerate(pk):
        p.time = 100 + i
    path = str(tmp_path / 't.pcap')
    wrpcap(path, pk)
    recs = list(pr.iter_any(path))
    assert [(pr.ip_to_str(r[1]), r[3], r[4], r[5]) for r in recs] == [('10.0.0.1', 6, 1234, 80), ('10.0.0.2', 17, 53, 5000), ('10.0.0.3', 1, 3, 3)]
    assert recs[0][6] == 0x02 and recs[0][0] == 100 and recs[1][7] == 20 + 8 + 4
    cache = str(tmp_path / 't.cache')
    assert pr.build_cache(path, cache) == 3
    feats = [pr.to_features(r) for r in pr.iter_any(cache)]
    assert feats[2]['icmp_type'] == 3 and feats[2]['dst_port'] is None and feats[1]['length'] == 32
    assert [r[:7] for r in pr.iter_cache(cache)] == [r[:7] for r in recs]  # legacy 7-tuple API on a v2 cache


def test_incident_grouping():
    rs = one_rule('syn_rate', 100)
    burst = lambda t0: [pkt(t0 + i / 1000, '10.0.0.9', '192.168.1.1', 1000 + i, 80) for i in range(150)]
    dets = run(rs, burst(1) + burst(2) + burst(200))
    inc = analyzer.group_incidents(dets)
    assert [(i['src'], i['seconds']) for i in inc] == [('10.0.0.9', 2), ('10.0.0.9', 1)]


@pytest.mark.skipif(not os.path.exists(SYNTHETIC), reason='synthetic pcap missing')
def test_analyze_synthetic():
    res = analyzer.analyze(SYNTHETIC, load_rules(RULES))
    s = res['summary']
    assert s['packets'] == 27905 and {p['protocol'] for p in s['protocols']} == {'TCP', 'UDP', 'ICMP'}
    assert {i['src'] for i in res['incidents']} == {f'192.168.10.{i}' for i in range(201, 206)}
