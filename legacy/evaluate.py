import os
from scapy.all import sniff
from nids.packet_parser import parse_packet
from nids.paths import SYNTHETIC_PCAP
from legacy.adaptive_engine import AdaptiveRuleEngine
from nids import alerts

# Ground Truth for our synthetic dataset
ATTACKERS = {f"192.168.10.{i}" for i in range(201, 206)}
BENIGN_HOSTS = {f"192.168.10.{i}" for i in range(10, 61)}

# Global store for captured alerts
captured_alerts = []

# Mock the alert function to capture it programmatically instead of printing
def mock_generate_alert(timestamp, rule_name, src_ip, details):
    captured_alerts.append((src_ip, rule_name))

from legacy import adaptive_engine
adaptive_engine.generate_alert = mock_generate_alert

def main():
    print("Starting Evaluation of Adaptive Rule Engine...")
    engine = AdaptiveRuleEngine()
    
    pcap_file = SYNTHETIC_PCAP
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} not found.")
        return

    def packet_callback(packet):
        features = parse_packet(packet)
        if features:
            engine.process_packet(features)

    sniff(offline=pcap_file, prn=packet_callback, store=False)
    engine.flush()

    # Analyze Results
    alerted_ips = set([alert[0] for alert in captured_alerts])
    
    true_positives = alerted_ips.intersection(ATTACKERS)
    false_positives = alerted_ips.intersection(BENIGN_HOSTS)
    
    total_attackers = len(ATTACKERS)
    total_benign = len(BENIGN_HOSTS)
    
    detection_rate = (len(true_positives) / total_attackers) * 100 if total_attackers else 0
    fp_rate = (len(false_positives) / total_benign) * 100 if total_benign else 0
    
    print("\n--- Evaluation Results ---")
    print(f"Total Packets Processed: (Read from PCAP)")
    print(f"True Attackers Detected: {len(true_positives)}/{total_attackers}")
    print(f"False Positives: {len(false_positives)}/{total_benign} benign hosts flagged")
    print("-" * 25)
    print(f"Detection Rate (Recall): {detection_rate:.2f}%")
    print(f"False Positive Rate:     {fp_rate:.2f}%")
    
    if fp_rate == 0 and detection_rate == 100:
        print("\nConclusion: Excellent performance! The adaptive rules perfectly separated normal traffic from attacks.")

if __name__ == "__main__":
    main()
