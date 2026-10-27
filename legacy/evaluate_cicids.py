"""
Evaluate rule engines on CICIDS2017/2018 dataset.

This script loads CICIDS CSV data, converts it to packet features,
and runs both Static and Adaptive engines with full metrics.
"""
import sys
import os
from legacy.cicids_adapter import CICIDSAdapter, print_dataset_stats
from legacy.rule_engine import StaticRuleEngine
from legacy.adaptive_engine import AdaptiveRuleEngine
from legacy import rule_engine
from legacy import adaptive_engine


def run_engine_on_cicids(engine_class, packets, engine_module, engine_name):
    """
    Run an engine on CICIDS packet features.
    
    Args:
        engine_class: StaticRuleEngine or AdaptiveRuleEngine
        packets: List of packet feature dicts
        engine_module: Module containing generate_alert (for monkey-patching)
        engine_name: Name for display
        
    Returns:
        List of (src_ip, rule_name) tuples
    """
    print(f"\n{'='*70}")
    print(f"Running {engine_name} on CICIDS dataset...")
    print(f"{'='*70}")
    
    captured_alerts = []
    
    def mock_generate_alert(timestamp, rule_name, src_ip, details):
        captured_alerts.append((src_ip, rule_name))
        # Print progress every 100 alerts
        if len(captured_alerts) % 100 == 0:
            print(f"  {len(captured_alerts)} alerts generated so far...")
    
    # Monkey-patch
    original_generate_alert = engine_module.generate_alert
    engine_module.generate_alert = mock_generate_alert
    
    try:
        engine = engine_class()
        
        # Process packets
        total = len(packets)
        for i, packet in enumerate(packets):
            if (i + 1) % 10000 == 0:
                print(f"  Processed {i+1}/{total} packets...")
            engine.process_packet(packet)
        
        engine.flush()
        
    finally:
        engine_module.generate_alert = original_generate_alert
    
    print(f"  Total alerts generated: {len(captured_alerts)}")
    return captured_alerts


def analyze_cicids_results(captured_alerts, ground_truth):
    """
    Analyze results against CICIDS ground truth.
    
    Args:
        captured_alerts: List of (src_ip, rule_name) tuples
        ground_truth: Dict from adapter.get_ground_truth()
        
    Returns:
        Dict with metrics
    """
    attackers = ground_truth['attackers']
    benign = ground_truth['benign']
    
    alerted_ips = set([src_ip for src_ip, _ in captured_alerts])
    
    true_positives = alerted_ips.intersection(attackers)
    false_positives = alerted_ips.intersection(benign)
    false_negatives = attackers - alerted_ips
    
    tp_count = len(true_positives)
    fp_count = len(false_positives)
    fn_count = len(false_negatives)
    
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
    recall = tp_count / len(attackers) if len(attackers) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'true_positives': tp_count,
        'false_positives': fp_count,
        'false_negatives': fn_count,
        'total_attackers': len(attackers),
        'total_benign': len(benign),
        'precision': precision * 100,
        'recall': recall * 100,
        'f1_score': f1 * 100,
        'alert_volume': len(captured_alerts),
        'alerted_ips': alerted_ips,
        'missed_attackers': false_negatives
    }


def print_comparison(static_results, adaptive_results, ground_truth):
    """
    Print comparative results.
    """
    print("\n" + "="*90)
    print("CICIDS EVALUATION RESULTS: Static vs Adaptive")
    print("="*90)
    
    print(f"\nDataset Overview:")
    print(f"  Total Attacker IPs: {ground_truth['total_attackers']}")
    print(f"  Total Benign IPs: {ground_truth['total_benign']}")
    
    print(f"\n{'Metric':<35} {'Static':<25} {'Adaptive':<25}")
    print("-"*90)
    
    print(f"{'True Positives (IPs detected)':<35} "
          f"{static_results['true_positives']}/{static_results['total_attackers']:<23} "
          f"{adaptive_results['true_positives']}/{adaptive_results['total_attackers']:<23}")
    
    print(f"{'False Positives (benign flagged)':<35} "
          f"{static_results['false_positives']}/{static_results['total_benign']:<23} "
          f"{adaptive_results['false_positives']}/{adaptive_results['total_benign']:<23}")
    
    print(f"{'False Negatives (missed)':<35} "
          f"{static_results['false_negatives']}/{static_results['total_attackers']:<23} "
          f"{adaptive_results['false_negatives']}/{adaptive_results['total_attackers']:<23}")
    
    print()
    print(f"{'Precision':<35} {static_results['precision']:.2f}%{'':<20} {adaptive_results['precision']:.2f}%")
    print(f"{'Recall (Detection Rate)':<35} {static_results['recall']:.2f}%{'':<20} {adaptive_results['recall']:.2f}%")
    print(f"{'F1-Score':<35} {static_results['f1_score']:.2f}%{'':<20} {adaptive_results['f1_score']:.2f}%")
    
    print()
    print(f"{'Total Alert Volume':<35} {static_results['alert_volume']:<25} {adaptive_results['alert_volume']:<25}")
    
    print("="*90)
    
    # Show some examples of missed attackers
    if static_results['missed_attackers']:
        print(f"\nExample IPs missed by Static (showing up to 5):")
        for ip in list(static_results['missed_attackers'])[:5]:
            attack_type = ground_truth['attack_types'].get(ip, 'Unknown')
            print(f"  {ip} - {attack_type}")
    
    if adaptive_results['missed_attackers']:
        print(f"\nExample IPs missed by Adaptive (showing up to 5):")
        for ip in list(adaptive_results['missed_attackers'])[:5]:
            attack_type = ground_truth['attack_types'].get(ip, 'Unknown')
            print(f"  {ip} - {attack_type}")
    
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python evaluate_cicids.py <path_to_cicids_csv>")
        print("\nYou need to download CICIDS2017 or CICIDS2018 dataset first.")
        print("See: https://www.unb.ca/cic/datasets/ids-2017.html")
        print("     https://www.unb.ca/cic/datasets/ids-2018.html")
        print("\nExample CSV files:")
        print("  - Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        print("  - Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)
    
    # Load dataset
    print("="*70)
    print("STEP 1: Loading CICIDS Dataset")
    print("="*70)
    adapter = CICIDSAdapter(csv_path)
    adapter.load()
    print_dataset_stats(adapter)
    
    # Get ground truth
    ground_truth = adapter.get_ground_truth()
    
    # Convert to packet features
    print("\n" + "="*70)
    print("STEP 2: Converting flows to packet features")
    print("="*70)
    packets = adapter.get_all_packets()
    print(f"Generated {len(packets)} packet features from {len(adapter.flows)} flows")
    
    # Run Static Engine
    print("\n" + "="*70)
    print("STEP 3: Evaluating StaticRuleEngine")
    print("="*70)
    static_alerts = run_engine_on_cicids(StaticRuleEngine, packets, rule_engine, "StaticRuleEngine")
    static_results = analyze_cicids_results(static_alerts, ground_truth)
    
    # Run Adaptive Engine
    print("\n" + "="*70)
    print("STEP 4: Evaluating AdaptiveRuleEngine")
    print("="*70)
    adaptive_alerts = run_engine_on_cicids(AdaptiveRuleEngine, packets, adaptive_engine, "AdaptiveRuleEngine")
    adaptive_results = analyze_cicids_results(adaptive_alerts, ground_truth)
    
    # Print comparison
    print("\n" + "="*70)
    print("STEP 5: Results Comparison")
    print("="*70)
    print_comparison(static_results, adaptive_results, ground_truth)


if __name__ == "__main__":
    main()
