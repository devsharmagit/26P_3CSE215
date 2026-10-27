"""
Tests for per-rule sliding windows (rule.window_seconds, revision 2 / R2): expected counts on tiny synthetic captures,
rule file validation, and the default rule file giving exactly the output it gave before the change.
Run (from the repository root):  python -m pytest -q
"""
import hashlib
import json
import os

import pytest

from nids import pcapng_reader as pr
from nids.engine import RuleEngine
from nids.rule_set import RuleFileError, load_rules, parse_rules
from test_engine import one_rule, pkt, rejected_syns, run

from nids.paths import RULES, SYNTHETIC_PCAP as SYNTHETIC


def ticks(t0, t1, step=1.0):
    """Unrelated UDP packets (outside home_net) that only move the clock forward."""
    out, t = [], t0
    while t <= t1:
        out.append(pkt(t, '10.0.0.1', '8.8.8.8', 5000, 53, proto=17))
        t += step
    return out


def burst(seconds, per_second, src='10.0.0.9', dst='192.168.1.1', ports=lambda i: 80):
    return [pkt(s + i / per_second, src, dst, 40000 + i, ports(i)) for s in seconds for i in range(per_second)]


def test_sliding_syn_rate_counts_the_last_w_seconds():
    # 50 SYNs/s during seconds 1-5, then nothing: 250 SYNs stay inside the 10 s window until the first ones expire
    pk = burst(range(1, 6), 50) + ticks(6.5, 20.5)
    dets = run(one_rule('syn_rate', 200, window_seconds=10), pk)
    assert [(d.time, d.hits[0].value) for d in dets] == [(5.0, 250), (6.5, 250), (7.5, 250), (8.5, 250), (9.5, 250),
                                                          (10.5, 225)]
    # the same traffic never exceeds 200 in any 1 s window
    assert run(one_rule('syn_rate', 200), pk) == []


def test_sliding_distinct_ports_unions_ports_across_seconds():
    # 5 new ports per second for 6 s (a slow sweep), then the same 5 ports again: 30 distinct ports in 10 s
    pk = burst(range(1, 7), 5, ports=lambda i: 1 + i) + ticks(7.5, 12.5)
    for p in pk[:30]:
        p['dst_port'] += int(p['timestamp'] - 1) * 5
    dets = run(one_rule('distinct_ports', 20, window_seconds=10), pk)
    assert max(h.value for d in dets for h in d.hits) == 30
    assert run(one_rule('distinct_ports', 20), pk) == []          # at most 5 per 1 s window
    repeat = burst(range(1, 7), 5, ports=lambda i: 1 + i) + ticks(7.5, 12.5)
    assert run(one_rule('distinct_ports', 20, window_seconds=10), repeat) == []  # 5 distinct ports, repeated


def test_sliding_victim_rule_attributes_the_sender_of_most_traffic_in_the_window():
    # 10.0.0.8 sends 20 connections in second 1; 10.0.0.9 sends 15 per second in seconds 2-3 (30 in total)
    pk = burst([1], 20, src='10.0.0.8') + burst([2, 3], 15, src='10.0.0.9') + ticks(4.5, 6.5)
    dets = run(one_rule('victim_conn_rate', 40, window_seconds=10), pk)
    assert dets and {d.src for d in dets} == {'10.0.0.9'} and dets[0].hits[0].value == 50
    assert run(one_rule('victim_conn_rate', 40), pk) == []


def test_window_equal_to_engine_window_is_the_existing_rule():
    pk = burst(range(1, 6), 50, ports=lambda i: i) + ticks(6.5, 9.5)
    for measure, value in (('syn_rate', 40), ('distinct_ports', 20), ('victim_conn_rate', 32)):
        a = [d.to_dict() for d in run(one_rule(measure, value), pk)]
        b = [d.to_dict() for d in run(one_rule(measure, value, window_seconds=1), pk)]
        assert a == b and a


def test_rejected_probes_rule_level_window_overrides_params():
    probes = rejected_syns(15, gap=1.0)  # one refused probe per second
    by_param = run(one_rule('rejected_probes', 2, params={'window_seconds': 1}), probes)
    by_rule = run(one_rule('rejected_probes', 2, window_seconds=1, params={'window_seconds': 60}), probes)
    assert by_param == [] and by_rule == []   # never more than 2 refusals in 1 s
    assert run(one_rule('rejected_probes', 2, window_seconds=10), probes)


@pytest.mark.parametrize('rule, msg', [
    ({'id': 'x', 'measure': 'port_entropy', 'window_seconds': 10, 'threshold': {'value': 4}}, 'has no window_seconds'),
    ({'id': 'x', 'measure': 'half_open_ratio', 'window_seconds': 10, 'threshold': {'value': 0.8}}, 'has no window_seconds'),
    ({'id': 'x', 'measure': 'syn_rate', 'window_seconds': 0.5, 'threshold': {'value': 1}}, 'window_seconds must be'),
    ({'id': 'x', 'measure': 'rejected_probes', 'window_seconds': 0, 'threshold': {'value': 1}}, 'window_seconds must be'),
])
def test_window_rule_file_errors(rule, msg):
    with pytest.raises(RuleFileError, match=msg):
        parse_rules({'rules': [rule]})


def test_default_rule_file_sets_no_rule_window():
    assert all(r.window_seconds is None for r in load_rules(RULES).rules)


# Fingerprints of the default rule file's detections on the synthetic capture, computed with the engine as it was
# before rule windows were added (commit 6525bee, engine.py/rule_set.py of a8ceacf).
DEFAULT_FINGERPRINTS = {
    'fixed': (100, '643e111948d2be1663007f9c7d5a133225f09103de4067749b4f61aad53d29ce'),
    'adaptive': (100, '9878dc87e85416256648d867f91be11feaa497aefc2bf09944119c1af1601391'),
}


@pytest.mark.skipif(not os.path.exists(SYNTHETIC), reason='synthetic pcap missing')
@pytest.mark.parametrize('policy', ['fixed', 'adaptive'])
def test_default_output_unchanged(policy):
    out = []
    eng = RuleEngine(load_rules(RULES).variant(policy=policy),
                     on_detection=lambda d: out.append(d.to_dict()))
    for r in pr.iter_any(SYNTHETIC):
        if r[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(r))
    eng.flush()
    digest = hashlib.sha256(json.dumps(out, sort_keys=True).encode()).hexdigest()
    assert (len(out), digest) == DEFAULT_FINGERPRINTS[policy]
