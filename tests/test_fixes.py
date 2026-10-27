"""
Deterministic tests for: (1) initiator-only port tracking, (2) baseline freeze, (3) per-victim rules.
Run:  python3 test_fixes.py   (also collectable by pytest)
"""
from legacy import adaptive_engine
from legacy import rule_engine
from legacy.adaptive_engine import AdaptiveRuleEngine
from legacy.rule_engine import StaticRuleEngine


def pkt(ts, src, dst, sport, dport, flags='S', proto=6):
    return {'timestamp': ts, 'src_ip': src, 'dst_ip': dst, 'protocol': proto,
            'src_port': sport, 'dst_port': dport, 'tcp_flags': flags if proto == 6 else None, 'length': 0}


def capture(module):
    alerts = []
    module.generate_alert = lambda ts, rule, src, details: alerts.append((rule, src))
    return alerts


def run(engine, packets):
    for p in packets:
        engine.process_packet(p)
    engine.flush()


def server_replies():
    """A DNS-like server answering 40 different clients within one second."""
    return [pkt(0.01 * i, '10.0.0.53', f'10.0.0.{100 + i}', 53, 40000 + i, flags=None, proto=17) for i in range(40)] + \
           [pkt(0.01 * i + 0.005, '10.0.0.80', f'10.0.0.{100 + i}', 80, 40000 + i, flags='SA') for i in range(40)]


def test_static_port_scan_ignores_server_replies():
    alerts = capture(rule_engine)
    run(StaticRuleEngine(victim_rules=False), server_replies())
    assert alerts == []
    alerts = capture(rule_engine)  # legacy behaviour reproduces the bug
    run(StaticRuleEngine(initiator_only_ports=False, victim_rules=False), server_replies())
    assert ('Port Scan', '10.0.0.53') in alerts


def test_static_port_scan_still_detects_real_scan():
    alerts = capture(rule_engine)
    run(StaticRuleEngine(victim_rules=False), [pkt(0.01 * i, '9.9.9.9', '10.0.0.1', 5000, 1 + i) for i in range(30)])
    assert ('Port Scan', '9.9.9.9') in alerts


def test_adaptive_entropy_ignores_server_replies():
    alerts = capture(adaptive_engine)
    run(AdaptiveRuleEngine(victim_rules=False), server_replies())
    assert not [a for a in alerts if a[0] == 'Entropy Port Scan']
    alerts = capture(adaptive_engine)
    run(AdaptiveRuleEngine(initiator_only_ports=False, victim_rules=False), server_replies())
    assert [a for a in alerts if a[0] == 'Entropy Port Scan']


def sustained_flood(seconds=30, rate=90):
    out = []
    for s in range(seconds):
        for i in range(rate):
            out.append(pkt(s + i / rate, '6.6.6.6', '10.0.0.1', 20000 + s * rate + i, 80))
    return out


def test_baseline_freeze_keeps_alerting_on_sustained_flood():
    alerts = capture(adaptive_engine)
    run(AdaptiveRuleEngine(baseline_freeze=False, victim_rules=False), sustained_flood())
    legacy = len([a for a in alerts if a[0] == 'Adaptive SYN Flood'])
    alerts = capture(adaptive_engine)
    run(AdaptiveRuleEngine(baseline_freeze=True, victim_rules=False), sustained_flood())
    frozen = len([a for a in alerts if a[0] == 'Adaptive SYN Flood'])
    assert legacy < 10, legacy       # EMA absorbs the attack
    assert frozen >= 28, frozen      # frozen baseline keeps firing every second


def test_baseline_unfreezes_after_attack_ends():
    eng = AdaptiveRuleEngine(victim_rules=False)
    alerts = capture(adaptive_engine)
    run(eng, sustained_flood(10))
    key = (id(eng.historical_syn_avg), '6.6.6.6')
    assert key in eng.frozen_until
    # quiet traffic well after the cool-down updates the baseline again
    late = [pkt(200 + s, '6.6.6.6', '10.0.0.1', 30000 + s, 80) for s in range(5)]
    before = eng.historical_syn_avg['6.6.6.6']
    run(eng, late)
    assert eng.historical_syn_avg['6.6.6.6'] != before


def distributed_flood():
    """200 different sources, each only 1 SYN/s: no per-source rule can fire."""
    return [pkt(s + i / 200, f'7.7.{i // 250}.{i % 250 + 1}', '192.168.10.50', 30000 + i, 80)
            for s in range(5) for i in range(200)]


def test_victim_connection_flood_catches_distributed_attack():
    alerts = capture(adaptive_engine)
    run(AdaptiveRuleEngine(), distributed_flood())
    assert [a for a in alerts if a[0] == 'Victim Connection Flood']
    assert not [a for a in alerts if a[0] == 'Adaptive SYN Flood']
    alerts = capture(adaptive_engine)
    run(AdaptiveRuleEngine(victim_rules=False), distributed_flood())
    assert alerts == []


def test_victim_rules_ignore_unprotected_and_download_traffic():
    alerts = capture(adaptive_engine)
    # 2000 pps of bulk data to an ephemeral port on a protected host (a download): not a flood
    pk = [pkt(i / 2000, '8.8.8.8', '192.168.10.15', 443, 50000, flags='A') for i in range(2000)]
    # heavy service-port traffic to a host outside protected_prefixes
    pk += [pkt(2 + i / 2000, '192.168.10.15', '8.8.8.8', 50000, 443, flags='A') for i in range(2000)]
    run(AdaptiveRuleEngine(), pk)
    assert not [a for a in alerts if a[0].startswith('Victim')]


def test_static_victim_packet_flood():
    alerts = capture(rule_engine)
    run(StaticRuleEngine(), [pkt(i / 600, f'5.5.5.{i % 200 + 1}', '192.168.10.50', 40000 + i, 80, flags='A') for i in range(600)])
    assert [a for a in alerts if a[0] == 'Victim Packet Flood']


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        t()
        print('ok  ', t.__name__)
    print(f'{len(tests)} tests passed')
