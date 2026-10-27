"""
Evaluate rule engines on CICIDS2017 MachineLearningCVE format.
"""
import sys
import os
from legacy.cicids_ml_adapter import CICIDSMLAdapter, print_dataset_stats
from legacy.rule_engine import StaticRuleEngine
from legacy.adaptive_engine import AdaptiveRuleEngine
from legacy import rule_engine
from legacy import adaptive_engine


def run_engine_on_cicids(engine_class, packets, engine_module, engine_name):
    """Run an engine on CICIDS packet features."""
    print(f"\n{'='*70}")
    print(f"Running {engine_name}...")
    print(f"{'='*70}")
    
    captured_alerts = []
    
    def mock_generate_alert(timestamp, rule_name, src_ip, details):
        captured_alerts.append((src_ip, rule_name))
        if len(captured_alerts) % 500 == 0:
            print(f"  {len(captured_alerts)} alerts generated...")
    
    original_generate_alert = engine_module.generate_alert
    engine_module.generate_alert = mock_generate_alert
    
    try:
        engine = engine_class()
        
        total = len(packets)
        for i, packet in enumerate(packets):
            if (i + 1) % 50000 == 0:
                print(f"  Processed {i+1}/{total} packets...")
            engine.process_packet(packet)
        
        engine.flush()
        
    finally:
        engine_module.generate_alert = original_generate_alert
    
    print(f"  ✓ Total alerts: {len(captured_alerts)}")
    return captured_alerts


def analyze_results(captured_alerts, ground_truth):
    """Analyze results against ground truth."""
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
        'missed_attackers': false_negatives
    }


def print_comparison(static_results, adaptive_results, ground_truth):
    """Print comparison table."""
    print("\n" + "="*90)
    print("CICIDS2017 EVALUATION RESULTS: Static vs Adaptive")
    print("="*90)
    
    print(f"\nDataset: {ground_truth['total_attackers']} attacker IPs, "
          f"{ground_truth['total_benign']} benign IPs (synthesized)")
    
    print(f"\n{'Metric':<40} {'Static':<25} {'Adaptive':<25}")
    print("-"*90)
    
    print(f"{'True Positives (attackers detected)':<40} "
          f"{static_results['true_positives']}/{static_results['total_attackers']:<23} "
          f"{adaptive_results['true_positives']}/{adaptive_results['total_attackers']:<23}")
    
    print(f"{'False Positives (benign flagged)':<40} "
          f"{static_results['false_positives']}/{static_results['total_benign']:<23} "
          f"{adaptive_results['false_positives']}/{adaptive_results['total_benign']:<23}")
    
    print()
    print(f"{'Precision':<40} {static_results['precision']:.2f}%{'':<20} "
          f"{adaptive_results['precision']:.2f}%")
    print(f"{'Recall (Detection Rate)':<40} {static_results['recall']:.2f}%{'':<20} "
          f"{adaptive_results['recall']:.2f}%")
    print(f"{'F1-Score':<40} {static_results['f1_score']:.2f}%{'':<20} "
          f"{adaptive_results['f1_score']:.2f}%")
    
    print()
    print(f"{'Total Alert Volume':<40} {static_results['alert_volume']:<25} "
          f"{adaptive_results['alert_volume']:<25}")
    
    print("="*90)
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python evaluate_cicids_ml.py <path_to_cicids_ml_csv> [max_flows]")
        print("\nThis script works with CICIDS2017 MachineLearningCVE format")
        print("(the anonymized version without IP addresses).")
        print("\nOptional max_flows parameter limits flows loaded (for quick testing).")
        print("Example: python evaluate_cicids_ml.py Wednesday-workingHours.pcap_ISCX.csv 10000")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    max_flows = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)
    
    # Load dataset
    print("="*70)
    print("STEP 1: Loading CICIDS MachineLearningCVE Dataset")
    print("="*70)
    adapter = CICIDSMLAdapter(csv_path)
    adapter.load(max_flows)
    print_dataset_stats(adapter)
    
    ground_truth = adapter.get_ground_truth()
    
    # Convert to packets
    print("\n" + "="*70)
    print("STEP 2: Converting flows to packet features")
    print("="*70)
    packets = adapter.get_all_packets()
    print(f"Generated {len(packets)} packets from {len(adapter.flows)} flows")
    
    # Run engines
    print("\n" + "="*70)
    print("STEP 3: Evaluating Both Engines")
    print("="*70)
    
    static_alerts = run_engine_on_cicids(StaticRuleEngine, packets, rule_engine, "StaticRuleEngine")
    static_results = analyze_results(static_alerts, ground_truth)
    
    adaptive_alerts = run_engine_on_cicids(AdaptiveRuleEngine, packets, adaptive_engine, "AdaptiveRuleEngine")
    adaptive_results = analyze_results(adaptive_alerts, ground_truth)
    
    # Print comparison
    print_comparison(static_results, adaptive_results, ground_truth)


if __name__ == "__main__":
    main()
