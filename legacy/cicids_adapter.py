"""
CICIDS2017/2018 Dataset Adapter

Converts CICIDS2017/2018 CSV flow records to the packet features format
expected by our rule engines.

Note: CICIDS datasets provide flow-level aggregated data, not per-packet data.
This adapter approximates packet-level features from flow metadata.
"""
import csv
import os
from collections import defaultdict


class CICIDSAdapter:
    """
    Adapter to convert CICIDS2017/2018 CSV flow records to packet feature dicts.
    """
    
    # Known attack labels in CICIDS2017/2018
    ATTACK_LABELS = {
        'BENIGN', 'DoS Hulk', 'PortScan', 'DDoS', 'DoS GoldenEye', 'FTP-Patator',
        'SSH-Patator', 'DoS slowloris', 'DoS Slowhttptest', 'Bot', 'Web Attack',
        'Infiltration', 'DoS slowloris', 'Heartbleed', 'Brute Force'
    }
    
    def __init__(self, csv_path):
        """
        Initialize adapter with path to CICIDS CSV file.
        
        Args:
            csv_path: Path to CICIDS2017/2018 CSV file
        """
        self.csv_path = csv_path
        self.flows = []
        self.ground_truth = {}  # src_ip -> label
        
    def load(self):
        """
        Load and parse the CSV file.
        
        Returns:
            Number of flows loaded
        """
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")
        
        print(f"Loading CICIDS dataset from {self.csv_path}...")
        
        with open(self.csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            # Handle different column name variations
            for row in reader:
                # Normalize column names (remove leading/trailing spaces)
                row = {k.strip(): v.strip() for k, v in row.items()}
                
                try:
                    flow = self._parse_flow(row)
                    if flow:
                        self.flows.append(flow)
                        
                        # Store ground truth
                        label = row.get('Label', row.get(' Label', 'BENIGN'))
                        self.ground_truth[flow['src_ip']] = label
                        
                except Exception as e:
                    # Skip malformed rows
                    continue
        
        print(f"Loaded {len(self.flows)} flows from {self.csv_path}")
        return len(self.flows)
    
    def _parse_flow(self, row):
        """
        Parse a single CSV row into a flow dict.
        
        Args:
            row: Dict from csv.DictReader
            
        Returns:
            Dict with flow metadata, or None if parsing fails
        """
        # Try different column name variations (CICIDS2017 vs 2018)
        src_ip = row.get('Source IP', row.get(' Source IP', row.get('Src IP', '')))
        dst_ip = row.get('Destination IP', row.get(' Destination IP', row.get('Dst IP', '')))
        src_port = row.get('Source Port', row.get(' Source Port', row.get('Src Port', '')))
        dst_port = row.get('Destination Port', row.get(' Destination Port', row.get('Dst Port', '')))
        protocol = row.get('Protocol', row.get(' Protocol', '0'))
        timestamp = row.get('Timestamp', row.get(' Timestamp', '0'))
        label = row.get('Label', row.get(' Label', 'BENIGN'))
        
        # Additional useful fields
        fwd_packets = row.get('Total Fwd Packets', row.get(' Total Fwd Packets', '1'))
        bwd_packets = row.get('Total Backward Packets', row.get(' Total Backward Packets', '0'))
        flow_duration = row.get('Flow Duration', row.get(' Flow Duration', '0'))
        
        if not src_ip or not dst_ip:
            return None
        
        try:
            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port) if src_port else None,
                'dst_port': int(dst_port) if dst_port else None,
                'protocol': self._parse_protocol(protocol),
                'timestamp': self._parse_timestamp(timestamp),
                'label': label.strip(),
                'fwd_packets': int(float(fwd_packets)) if fwd_packets else 1,
                'bwd_packets': int(float(bwd_packets)) if bwd_packets else 0,
                'flow_duration': float(flow_duration) if flow_duration else 0.0
            }
        except ValueError:
            return None
    
    def _parse_protocol(self, protocol_str):
        """
        Convert protocol string to numeric value.
        
        Returns:
            6 for TCP, 17 for UDP, 1 for ICMP, 0 for unknown
        """
        protocol_str = str(protocol_str).strip().upper()
        
        # Try numeric first
        try:
            return int(protocol_str)
        except ValueError:
            pass
        
        # Map common names
        protocol_map = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1,
            'ICMPV6': 58,
        }
        return protocol_map.get(protocol_str, 0)
    
    def _parse_timestamp(self, timestamp_str):
        """
        Parse timestamp string to float (Unix epoch seconds).
        
        For CICIDS, timestamps are often human-readable dates.
        We'll use a simple counter-based approach for relative ordering.
        """
        # For simplicity, use flow index as relative time
        # In a real implementation, parse actual datetime
        return float(len(self.flows))
    
    def to_packet_features(self, flow):
        """
        Convert a flow record to our packet features format.
        
        Since flows aggregate multiple packets, we approximate by generating
        representative "synthetic packets" from the flow metadata.
        
        Args:
            flow: Flow dict from _parse_flow
            
        Returns:
            List of packet feature dicts (one or more per flow)
        """
        packets = []
        
        # Approximate TCP flags based on flow characteristics
        tcp_flags = None
        if flow['protocol'] == 6:  # TCP
            # If flow has forward packets but no backward, assume SYN-only (half-open)
            if flow['fwd_packets'] > 0 and flow['bwd_packets'] == 0:
                tcp_flags = 'S'
            elif flow['bwd_packets'] > 0:
                # Bidirectional flow suggests established connection
                tcp_flags = 'A'
            else:
                tcp_flags = 'S'
        
        # Generate packets (we'll generate one packet per forward packet in the flow)
        num_packets = max(1, flow['fwd_packets'])
        
        # To avoid overwhelming the engine with too many packets per flow,
        # cap at a reasonable number (e.g., 10 representative packets per flow)
        num_packets = min(num_packets, 10)
        
        for i in range(num_packets):
            # Spread packets across the flow duration
            time_offset = (flow['flow_duration'] / 1_000_000.0) * (i / num_packets) if flow['flow_duration'] > 0 else 0
            
            packet = {
                'timestamp': flow['timestamp'] + time_offset,
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'protocol': flow['protocol'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port'],
                'tcp_flags': tcp_flags,
                'length': 60  # Approximate packet size
            }
            packets.append(packet)
        
        return packets
    
    def get_ground_truth(self):
        """
        Get ground truth labels for evaluation.
        
        Returns:
            Dict mapping attack categories to sets of source IPs:
            {
                'attackers': set of IPs,
                'benign': set of IPs,
                'attack_types': dict of IP -> specific attack label
            }
        """
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
        """
        Generate all packet features from all flows.
        
        Returns:
            List of packet feature dicts
        """
        all_packets = []
        for flow in self.flows:
            packets = self.to_packet_features(flow)
            all_packets.extend(packets)
        
        # Sort by timestamp
        all_packets.sort(key=lambda p: p['timestamp'])
        return all_packets


def print_dataset_stats(adapter):
    """
    Print statistics about the loaded CICIDS dataset.
    """
    gt = adapter.get_ground_truth()
    
    print("\n" + "="*70)
    print("CICIDS Dataset Statistics")
    print("="*70)
    print(f"Total Flows: {len(adapter.flows)}")
    print(f"Benign Hosts: {len(gt['benign'])}")
    print(f"Attacker Hosts: {len(gt['attackers'])}")
    print()
    
    # Count attack types
    attack_type_counts = defaultdict(int)
    for label in gt['attack_types'].values():
        attack_type_counts[label] += 1
    
    print("Attack Type Distribution:")
    for attack_type, count in sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {attack_type}: {count} hosts")
    print("="*70)
    print()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cicids_adapter.py <path_to_cicids_csv>")
        print("\nExample: python cicids_adapter.py Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    
    adapter = CICIDSAdapter(csv_path)
    adapter.load()
    print_dataset_stats(adapter)
    
    # Show sample packets
    packets = adapter.get_all_packets()
    print(f"\nGenerated {len(packets)} packet features from flows")
    print(f"\nSample packet features (first 3):")
    for i, packet in enumerate(packets[:3]):
        print(f"\nPacket {i+1}:")
        for key, value in packet.items():
            print(f"  {key}: {value}")
