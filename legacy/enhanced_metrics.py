"""
Enhanced evaluation metrics for NIDS engines.
Computes per-packet precision/recall/F1, time-to-detection, and alert volume.
"""
import os
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

# Attack timing windows from realistic_pcap_generator.py
# (base_time + start_offset, duration in seconds)
ATTACK_WINDOWS = {
    "192.168.10.201": (10.0, 0.5),    # Fast SYN flood
    "192.168.10.202": (20.0, 15.0),   # Slow SYN flood
    "192.168.10.203": (30.0, 0.6),    # ICMP flood
    "192.168.10.204": (40.0, 15.0),   # Stealthy port scan
    "192.168.10.205": (55.0, 0.5),    # Fast port scan
}


def label_packet(features, base_time):
    """
    Label a packet as 'attack' or 'benign' based on ground truth.
    
    Args:
        features: Packet feature dict
        base_time: Base timestamp of the capture (first packet time)
    
    Returns:
        'attack' or 'benign'
    """
    src_ip = features['src_ip']
    packet_time = features['timestamp']
    relative_time = packet_time - base_time
    
    if src_ip in ATTACKERS:
        # An attacker's packet is an attack only inside that attacker's window (1 s tolerance for the
        # generator's base_time vs first-packet offset); outside it the host is idle/benign.
        if src_ip in ATTACK_WINDOWS:
            start, duration = ATTACK_WINDOWS[src_ip]
            if start - 1.0 <= relative_time <= (start + duration + 1.0):
                return 'attack'
        return 'benign'
    elif src_ip in BENIGN_HOSTS:
        return 'benign'
    else:
        # Unknown IP (shouldn't happen in our synthetic data)
        return 'unknown'


def run_engine_with_detailed_metrics(engine_class, pcap_file, engine_module):
    """
    Run engine and collect detailed per-packet and per-alert metrics.
    
    Returns:
        Dict with detailed metrics
    """
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} not found.")
        return None
    
    # State tracking
    captured_alerts = []  # (timestamp, rule_name, src_ip, details)
    packets = []  # (timestamp, src_ip, label)
    first_malicious_packet = {}  # src_ip -> timestamp of first attack packet
    first_alert = {}  # src_ip -> timestamp of first alert
    base_time = None
    
    def mock_generate_alert(timestamp, rule_name, src_ip, details):
        captured_alerts.append((timestamp, rule_name, src_ip, details))
        # Track first alert per attacker
        if src_ip not in first_alert:
            first_alert[src_ip] = timestamp
    
    # Monkey-patch
    original_generate_alert = engine_module.generate_alert
    engine_module.generate_alert = mock_generate_alert
    
    try:
        engine = engine_class()
        
        def packet_callback(packet):
            nonlocal base_time
            features = parse_packet(packet)
            if features:
                # Set base_time from first packet
                if base_time is None:
                    base_time = features['timestamp']
                
                # Label packet
                label = label_packet(features, base_time)
                packets.append((features['timestamp'], features['src_ip'], label))
                
                # Track first malicious packet per attacker
                if label == 'attack' and features['src_ip'] not in first_malicious_packet:
                    first_malicious_packet[features['src_ip']] = features['timestamp']
                
                # Process through engine
                engine.process_packet(features)
        
        sniff(offline=pcap_file, prn=packet_callback, store=False)
        engine.flush()
        
    finally:
        engine_module.generate_alert = original_generate_alert
    
    # Compute metrics
    return compute_detailed_metrics(
        packets, captured_alerts, first_malicious_packet, first_alert, base_time
    )


def compute_detailed_metrics(packets, captured_alerts, first_malicious, first_alert, base_time):
    """
    Compute precision, recall, F1, time-to-detection, and alert volume metrics.
    """
    # Per-packet ground truth
    total_attack_packets = sum(1 for _, _, label in packets if label == 'attack')
    total_benign_packets = sum(1 for _, _, label in packets if label == 'benign')
    
    # Alert-level metrics (treat each alert as a "detection")
    alerted_ips = set([src_ip for _, _, src_ip, _ in captured_alerts])
    true_positive_ips = alerted_ips.intersection(ATTACKERS)
    false_positive_ips = alerted_ips.intersection(BENIGN_HOSTS)
    false_negative_ips = ATTACKERS - alerted_ips
    
    # IP-level precision/recall/F1
    tp_count = len(true_positive_ips)
    fp_count = len(false_positive_ips)
    fn_count = len(false_negative_ips)
    
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
    recall = tp_count / len(ATTACKERS) if len(ATTACKERS) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    # Time-to-detection for each detected attacker
    time_to_detect = {}
    for attacker in true_positive_ips:
        if attacker in first_malicious and attacker in first_alert:
            ttd = first_alert[attacker] - first_malicious[attacker]
            time_to_detect[attacker] = ttd
    
    avg_time_to_detect = sum(time_to_detect.values()) / len(time_to_detect) if time_to_detect else 0
    
    # Alert volume
    alert_volume = len(captured_alerts)
    
    # Compute capture duration for per-hour FP rate
    if packets:
        capture_duration_seconds = packets[-1][0] - packets[0][0]
        capture_duration_hours = capture_duration_seconds / 3600.0
        fp_per_hour = fp_count / capture_duration_hours if capture_duration_hours > 0 else 0
    else:
        capture_duration_seconds = 0
        fp_per_hour = 0
    
    return {
        'total_packets': len(packets),
        'attack_packets': total_attack_packets,
        'benign_packets': total_benign_packets,
        'alert_volume': alert_volume,
        'true_positive_ips': len(true_positive_ips),
        'false_positive_ips': len(false_positive_ips),
        'false_negative_ips': len(false_negative_ips),
        'precision': precision * 100,
        'recall': recall * 100,
        'f1_score': f1 * 100,
        'avg_time_to_detect': avg_time_to_detect,
        'time_to_detect_per_attacker': time_to_detect,
        'fp_per_hour': fp_per_hour,
        'capture_duration_seconds': capture_duration_seconds,
        'missed_attackers': list(false_negative_ips)
    }


def print_detailed_comparison(static_metrics, adaptive_metrics):
    """
    Print a comprehensive comparison table.
    """
    print("\n" + "="*90)
    print("ENHANCED METRICS COMPARISON: Static vs Adaptive")
    print("="*90)
    
    print(f"\n{'Metric':<35} {'Static':<25} {'Adaptive':<25}")
    print("-"*90)
    
    # Dataset info
    print(f"{'Total Packets Processed':<35} {static_metrics['total_packets']:<25} {adaptive_metrics['total_packets']:<25}")
    print(f"{'  Attack Packets':<35} {static_metrics['attack_packets']:<25} {adaptive_metrics['attack_packets']:<25}")
    print(f"{'  Benign Packets':<35} {static_metrics['benign_packets']:<25} {adaptive_metrics['benign_packets']:<25}")
    
    print()
    # Detection metrics
    print(f"{'True Positives (IPs)':<35} {static_metrics['true_positive_ips']}/5{'':<20} {adaptive_metrics['true_positive_ips']}/5")
    print(f"{'False Positives (IPs)':<35} {static_metrics['false_positive_ips']}/51{'':<19} {adaptive_metrics['false_positive_ips']}/51")
    print(f"{'False Negatives (IPs)':<35} {static_metrics['false_negative_ips']}/5{'':<20} {adaptive_metrics['false_negative_ips']}/5")
    
    print()
    # Core metrics
    print(f"{'Precision':<35} {static_metrics['precision']:.2f}%{'':<20} {adaptive_metrics['precision']:.2f}%")
    print(f"{'Recall (Detection Rate)':<35} {static_metrics['recall']:.2f}%{'':<20} {adaptive_metrics['recall']:.2f}%")
    print(f"{'F1-Score':<35} {static_metrics['f1_score']:.2f}%{'':<20} {adaptive_metrics['f1_score']:.2f}%")
    
    print()
    # Alert fatigue
    print(f"{'Total Alert Volume':<35} {static_metrics['alert_volume']:<25} {adaptive_metrics['alert_volume']:<25}")
    print(f"{'FP Rate (per hour)':<35} {static_metrics['fp_per_hour']:.2f}{'':<22} {adaptive_metrics['fp_per_hour']:.2f}")
    
    print()
    # Time to detection
    print(f"{'Avg Time-to-Detection (sec)':<35} {static_metrics['avg_time_to_detect']:.3f}s{'':<20} {adaptive_metrics['avg_time_to_detect']:.3f}s")
    
    print()
    # Missed attackers
    if static_metrics['missed_attackers']:
        print(f"{'Missed by Static:':<35} {', '.join(static_metrics['missed_attackers'])}")
    if adaptive_metrics['missed_attackers']:
        print(f"{'Missed by Adaptive:':<35} {', '.join(adaptive_metrics['missed_attackers'])}")
    
    print("="*90)
    print()
    
    # Per-attacker time-to-detection breakdown
    print("Time-to-Detection Per Attacker:")
    print(f"{'Attacker IP':<20} {'Static (sec)':<20} {'Adaptive (sec)':<20}")
    print("-"*60)
    all_attackers = set(static_metrics['time_to_detect_per_attacker'].keys()) | \
                    set(adaptive_metrics['time_to_detect_per_attacker'].keys())
    for attacker in sorted(all_attackers):
        static_ttd = static_metrics['time_to_detect_per_attacker'].get(attacker, 'N/A')
        adaptive_ttd = adaptive_metrics['time_to_detect_per_attacker'].get(attacker, 'N/A')
        static_str = f"{static_ttd:.3f}" if isinstance(static_ttd, float) else static_ttd
        adaptive_str = f"{adaptive_ttd:.3f}" if isinstance(adaptive_ttd, float) else adaptive_ttd
        print(f"{attacker:<20} {static_str:<20} {adaptive_str:<20}")
    print()


def main():
    pcap_file = SYNTHETIC_PCAP
    
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} not found. Run realistic_pcap_generator.py first.")
        return
    
    print("Starting Enhanced Metrics Evaluation...")
    print(f"Dataset: {pcap_file}\n")
    
    # Run Static Engine
    print("Evaluating StaticRuleEngine...")
    static_metrics = run_engine_with_detailed_metrics(StaticRuleEngine, pcap_file, rule_engine)
    
    # Run Adaptive Engine
    print("Evaluating AdaptiveRuleEngine...")
    adaptive_metrics = run_engine_with_detailed_metrics(AdaptiveRuleEngine, pcap_file, adaptive_engine)
    
    # Print comparison
    print_detailed_comparison(static_metrics, adaptive_metrics)


if __name__ == "__main__":
    main()
