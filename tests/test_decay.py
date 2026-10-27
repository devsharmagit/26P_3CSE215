"""
Test to verify port_frequencies decay and connection pruning work correctly.
"""
from legacy.adaptive_engine import AdaptiveRuleEngine

def test_port_decay():
    """Test that port frequencies decay over time."""
    engine = AdaptiveRuleEngine()
    
    # Simulate packets hitting different ports
    for i in range(10):
        features = {
            'timestamp': 0.0 + (i * 0.1),
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'protocol': 6,  # TCP
            'src_port': 12345,
            'dst_port': 80 + i,
            'tcp_flags': 'S',
            'length': 60
        }
        engine.process_packet(features)
    
    # Check initial port count
    initial_ports = len(engine.port_frequencies['192.168.1.100'])
    print(f"Initial port count: {initial_ports}")
    print(f"Initial port frequencies: {dict(engine.port_frequencies['192.168.1.100'])}")
    
    # Trigger window rollover (decay applied)
    features = {
        'timestamp': 1.5,  # Move to next window
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.1',
        'protocol': 6,
        'src_port': 12345,
        'dst_port': 90,
        'tcp_flags': 'S',
        'length': 60
    }
    engine.process_packet(features)
    
    # Check post-decay
    after_decay_ports = len(engine.port_frequencies['192.168.1.100'])
    print(f"\nAfter 1 window (decay factor {engine.port_decay_factor}):")
    print(f"Port count: {after_decay_ports}")
    print(f"Port frequencies: {dict(engine.port_frequencies['192.168.1.100'])}")
    
    # Trigger multiple more windows to see pruning
    for window in range(5):
        features['timestamp'] = 2.5 + window
        engine.process_packet(features)
    
    final_ports = len(engine.port_frequencies['192.168.1.100'])
    print(f"\nAfter 5 more windows:")
    print(f"Port count: {final_ports}")
    print(f"Port frequencies: {dict(engine.port_frequencies['192.168.1.100'])}")
    print(f"\n✓ Decay working: ports dropped from {initial_ports} → {after_decay_ports} → {final_ports}")
    assert initial_ports == 10
    assert 80 not in engine.port_frequencies['192.168.1.100']      # old ports fully decayed
    assert final_ports == 1                                         # only the continuously refreshed port 90 remains


def test_connection_pruning():
    """Test that old connections are pruned after timeout."""
    engine = AdaptiveRuleEngine()
    engine.connection_timeout = 5.0  # Short timeout for testing
    
    # Create some connections
    for i in range(5):
        features = {
            'timestamp': 0.0 + (i * 0.1),
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'protocol': 6,
            'src_port': 10000 + i,
            'dst_port': 80,
            'tcp_flags': 'S',
            'length': 60
        }
        engine.process_packet(features)
    
    initial_conns = len(engine.connections)
    print(f"\nInitial connections: {initial_conns}")
    
    # Move forward past the timeout
    features = {
        'timestamp': 10.0,  # 10 seconds later, past 5s timeout
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.1',
        'protocol': 6,
        'src_port': 20000,
        'dst_port': 80,
        'tcp_flags': 'S',
        'length': 60
    }
    engine.process_packet(features)
    
    after_pruning = len(engine.connections)
    print(f"After {engine.connection_timeout}s timeout: {after_pruning} connections")
    print(f"✓ Pruning working: connections dropped from {initial_conns} → {after_pruning}")
    assert initial_conns == 5
    assert after_pruning == 1  # the 5 stale tuples are gone; only the fresh one added at t=10 remains


if __name__ == "__main__":
    print("="*60)
    print("Testing Port Frequency Decay")
    print("="*60)
    test_port_decay()
    
    print("\n" + "="*60)
    print("Testing Connection Pruning")
    print("="*60)
    test_connection_pruning()
    
    print("\n" + "="*60)
    print("All tests passed! Memory growth is now bounded.")
    print("="*60)


def test_long_gap_decays_more_than_one_window():
    """A 10-window quiet gap must decay port counts by 0.5**10, not just once."""
    engine = AdaptiveRuleEngine()
    engine.port_frequencies['h'][80] = 1000.0
    base = {'timestamp': 0.0, 'src_ip': 'h', 'dst_ip': 'd', 'protocol': 6, 'src_port': 1, 'dst_port': 81, 'tcp_flags': 'S', 'length': 60}
    engine.process_packet(base)
    engine.process_packet(dict(base, timestamp=11.5))
    assert engine.port_frequencies['h'][80] < 2.0, engine.port_frequencies['h'][80]
