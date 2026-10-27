"""
Unified benchmark harness for comparing StaticRuleEngine vs AdaptiveRuleEngine.
"""
import os
import sys
from scapy.all import sniff
from nids.packet_parser import parse_packet
from nids.paths import SYNTHETIC_PCAP
from legacy.rule_engine import StaticRuleEngine
from legacy.adaptive_engine import AdaptiveRuleEngine
from legacy import rule_engine
from legacy import adaptive_engine

# Ground Truth for our synthetic dataset
ATTACKERS = {f"192.168.10.{i}" for i in range(201, 206)}
BENIGN_HOSTS = {f"192.168.10.{i}" for i in range(10, 61)}


def run_engine(engine_class, pcap_file, engine_module):
    """
    Run a given engine class over a pcap file and return captured alerts.
    
    Args:
        engine_class: Either StaticRuleEngine or AdaptiveRuleEngine class
        pcap_file: Path to pcap file
        engine_module: The module containing generate_alert to patch (rule_engine or adaptive_engine)
    
    Returns:
        List of (src_ip, rule_name) tuples for all alerts fired
    """
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} not found.")
        return []
    
    # Capture alerts in a list
    captured_alerts = []
    
    def mock_generate_alert(timestamp, rule_name, src_ip, details):
        captured_alerts.append((src_ip, rule_name))
    
    # Monkey-patch the generate_alert in the appropriate module
    original_generate_alert = engine_module.generate_alert
    engine_module.generate_alert = mock_generate_alert
    
    try:
        # Initialize engine
        engine = engine_class()
        
        # Process packets
        def packet_callback(packet):
            features = parse_packet(packet)
            if features:
                engine.process_packet(features)
        
        sniff(offline=pcap_file, prn=packet_callback, store=False)
        engine.flush()
        
    finally:
        # Restore original function
        engine_module.generate_alert = original_generate_alert
    
    return captured_alerts


def analyze_results(captured_alerts, engine_name):
    """
    Analyze captured alerts and compute metrics.
    
    Returns:
        Dict with metrics: detection_rate, fp_rate, alert_volume, etc.
    """
    alerted_ips = set([alert[0] for alert in captured_alerts])
    
    true_positives = alerted_ips.intersection(ATTACKERS)
    false_positives = alerted_ips.intersection(BENIGN_HOSTS)
    
    total_attackers = len(ATTACKERS)
    total_benign = len(BENIGN_HOSTS)
    
    detection_rate = (len(true_positives) / total_attackers) * 100 if total_attackers else 0
    fp_rate = (len(false_positives) / total_benign) * 100 if total_benign else 0
    alert_volume = len(captured_alerts)
    
    return {
        'engine_name': engine_name,
        'true_positives': len(true_positives),
        'total_attackers': total_attackers,
        'false_positives': len(false_positives),
        'total_benign': total_benign,
        'detection_rate': detection_rate,
        'fp_rate': fp_rate,
        'alert_volume': alert_volume,
        'alerted_ips': alerted_ips
    }


def print_comparison_table(results_list):
    """
    Print a side-by-side comparison table of results.
    """
    print("\n" + "="*80)
    print("STATIC vs ADAPTIVE ENGINE COMPARISON")
    print("="*80)
    print()
    print(f"{'Engine':<20} {'Detection Rate':<20} {'FP Rate':<20} {'Alert Volume':<15}")
    print("-"*80)
    
    for result in results_list:
        print(f"{result['engine_name']:<20} "
              f"{result['detection_rate']:>6.2f}% ({result['true_positives']}/{result['total_attackers']})      "
              f"{result['fp_rate']:>6.2f}% ({result['false_positives']}/{result['total_benign']})      "
              f"{result['alert_volume']:<15}")
    
    print("="*80)
    print()
    
    # Detailed breakdown
    for result in results_list:
        print(f"\n--- {result['engine_name']} Detailed Results ---")
        print(f"True Attackers Detected: {result['true_positives']}/{result['total_attackers']}")
        print(f"False Positives: {result['false_positives']}/{result['total_benign']} benign hosts flagged")
        print(f"Total Alerts Fired: {result['alert_volume']}")
        print(f"Detection Rate (Recall): {result['detection_rate']:.2f}%")
        print(f"False Positive Rate: {result['fp_rate']:.2f}%")


def main():
    pcap_file = SYNTHETIC_PCAP
    
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} not found. Run realistic_pcap_generator.py first.")
        sys.exit(1)
    
    print("Starting Benchmark: Static vs Adaptive Rule Engines...")
    print(f"Dataset: {pcap_file}")
    print()
    
    # Run Static Engine
    print("Running StaticRuleEngine...")
    static_alerts = run_engine(StaticRuleEngine, pcap_file, rule_engine)
    static_results = analyze_results(static_alerts, "StaticRuleEngine")
    
    # Run Adaptive Engine
    print("Running AdaptiveRuleEngine...")
    adaptive_alerts = run_engine(AdaptiveRuleEngine, pcap_file, adaptive_engine)
    adaptive_results = analyze_results(adaptive_alerts, "AdaptiveRuleEngine")
    
    # Print comparison
    print_comparison_table([static_results, adaptive_results])


if __name__ == "__main__":
    main()
