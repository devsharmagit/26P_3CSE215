"""
CICIDS2017 MachineLearningCVE Adapter

This adapter handles the CICIDS2017 "MachineLearningCVE" format which contains
only flow statistics (no IP addresses). We synthesize IPs based on flow patterns
to enable our packet-level rule engines to operate.
"""
import csv
import os
import hashlib
from collections import defaultdict


class CICIDSMLAdapter:
    """
    Adapter for CICIDS2017 MachineLearningCVE format (anonymized flows).
    """
    
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self.flows = []
        self.ground_truth = {}
        self.ip_counter = 1
        
    def load(self, max_flows=None):
        """
        Load and parse the CSV file.
        
        Args:
            max_flows: Optional limit on number of flows to load (for testing)
            
        Returns:
            Number of flows loaded
        """
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")
        
        print(f"Loading CICIDS MachineLearningCVE dataset from {self.csv_path}...")
        
        with open(self.csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            for i, row in enumerate(reader):
                if max_flows and i >= max_flows:
                    break
                    
                # Normalize column names
                row = {k.strip(): v.strip() for k, v in row.items()}
                
                try:
                    flow = self._parse_flow(row, i)
                    if flow:
                        self.flows.append(flow)
                        
                        # Store ground truth
                        label = row.get('Label', row.get(' Label', 'BENIGN')).strip()
                        self.ground_truth[flow['src_ip']] = label
                        
                except Exception as e:
                    continue
        
        print(f"Loaded {len(self.flows)} flows from {self.csv_path}")
        return len(self.flows)
    
    def _parse_flow(self, row, flow_id):
        """
        Parse a single CSV row into a flow dict.
        
        Since there are no IP addresses in this format, we synthesize them
        based on the flow's attack label and pattern.
        """
        # Get flow characteristics
        dst_port = row.get('Destination Port', row.get(' Destination Port', '0'))
        protocol = row.get('Protocol', row.get(' Protocol', '6'))  # Default TCP
        label = row.get('Label', row.get(' Label', 'BENIGN')).strip()
        
        # Flow statistics
        fwd_packets = row.get('Total Fwd Packets', row.get(' Total Fwd Packets', '1'))
        bwd_packets = row.get('Total Backward Packets', row.get(' Total Backward Packets', '0'))
        flow_duration = row.get('Flow Duration', row.get(' Flow Duration', '0'))
        syn_flag_count = row.get('SYN Flag Count', row.get(' SYN Flag Count', '0'))
        ack_flag_count = row.get('ACK Flag Count', row.get(' ACK Flag Count', '0'))
        
        # Synthesize IP addresses
        # Strategy: Group flows by attack type to simulate multiple attacks from same IPs
        if label.upper() == 'BENIGN':
            # Benign: distribute across many IPs (simulate normal users)
            src_ip = f"192.168.{(flow_id % 50) + 10}.{(flow_id // 50) % 250 + 1}"
        else:
            # Attack: group by attack type (simulate attackers)
            # Create a hash of the label to get consistent IP grouping
            label_hash = int(hashlib.md5(label.encode()).hexdigest()[:4], 16)
            attacker_id = (label_hash % 20) + 1  # 20 potential attacker IPs per attack type
            src_ip = f"10.{(label_hash % 200) + 10}.{attacker_id}.{(flow_id % 10) + 1}"
        
        dst_ip = "172.16.0.1"  # Single destination (typical for DoS/DDoS)
        
        try:
            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': 10000 + (flow_id % 50000),  # Synthesize source port
                'dst_port': int(dst_port) if dst_port and dst_port != '' else 80,
                'protocol': self._parse_protocol(protocol),
                'timestamp': float(flow_id),  # Use flow index as relative time
                'label': label,
                'fwd_packets': int(float(fwd_packets)) if fwd_packets else 1,
                'bwd_packets': int(float(bwd_packets)) if bwd_packets else 0,
                'flow_duration': float(flow_duration) if flow_duration else 0.0,
                'syn_flag_count': int(float(syn_flag_count)) if syn_flag_count else 0,
                'ack_flag_count': int(float(ack_flag_count)) if ack_flag_count else 0,
            }
        except (ValueError, TypeError) as e:
            return None
    
    def _parse_protocol(self, protocol_str):
        """Convert protocol to numeric."""
        try:
            return int(protocol_str)
        except (ValueError, TypeError):
            return 6  # Default TCP
    
    def to_packet_features(self, flow):
        """
        Convert a flow to packet features.
        """
        packets = []
        
        # Determine TCP flags based on flow characteristics
        tcp_flags = None
        if flow['protocol'] == 6:  # TCP
            if flow['syn_flag_count'] > 0 and flow['ack_flag_count'] == 0:
                tcp_flags = 'S'  # SYN-only (half-open)
            elif flow['ack_flag_count'] > 0:
                tcp_flags = 'A'  # Established
            else:
                tcp_flags = 'S'
        
        # Generate packets based on forward packet count
        num_packets = max(1, min(flow['fwd_packets'], 10))  # Cap at 10 per flow
        
        for i in range(num_packets):
            time_offset = (flow['flow_duration'] / 1_000_000.0) * (i / num_packets) if flow['flow_duration'] > 0 else 0
            
            packet = {
                'timestamp': flow['timestamp'] + time_offset,
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'protocol': flow['protocol'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port'],
                'tcp_flags': tcp_flags,
                'length': 60
            }
            packets.append(packet)
        
        return packets
    
    def get_ground_truth(self):
        """Get ground truth labels."""
        attackers = set()
        benign = set()
        attack_types = {}
        
        for src_ip, label in self.ground_truth.items():
            if label.upper() == 'BENIGN':
                benign.add(src_ip)
            else:
                attackers.add(src_ip)
                attack_types[src_ip] = label
        
        return {
            'attackers': attackers,
            'benign': benign,
            'attack_types': attack_types,
            'total_attackers': len(attackers),
            'total_benign': len(benign)
        }
    
    def get_all_packets(self):
        """Generate all packet features from all flows."""
        all_packets = []
        for flow in self.flows:
            packets = self.to_packet_features(flow)
            all_packets.extend(packets)
        
        all_packets.sort(key=lambda p: p['timestamp'])
        return all_packets


def print_dataset_stats(adapter):
    """Print statistics about the loaded dataset."""
    gt = adapter.get_ground_truth()
    
    print("\n" + "="*70)
    print("CICIDS MachineLearningCVE Dataset Statistics")
    print("="*70)
    print(f"Total Flows: {len(adapter.flows)}")
    print(f"Benign Flows: {sum(1 for f in adapter.flows if f['label'].upper() == 'BENIGN')}")
    print(f"Attack Flows: {sum(1 for f in adapter.flows if f['label'].upper() != 'BENIGN')}")
    print()
    print(f"Synthesized Benign IPs: {len(gt['benign'])}")
    print(f"Synthesized Attacker IPs: {len(gt['attackers'])}")
    print()
    
    # Count attack types
    attack_type_counts = defaultdict(int)
    for flow in adapter.flows:
        if flow['label'].upper() != 'BENIGN':
            attack_type_counts[flow['label']] += 1
    
    print("Attack Type Distribution:")
    for attack_type, count in sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {attack_type}: {count} flows")
    print("="*70)
    print()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cicids_ml_adapter.py <path_to_cicids_ml_csv> [max_flows]")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    max_flows = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    adapter = CICIDSMLAdapter(csv_path)
    adapter.load(max_flows)
    print_dataset_stats(adapter)
    
    packets = adapter.get_all_packets()
    print(f"\nGenerated {len(packets)} packet features from flows")
