from collections import defaultdict
from nids.alerts import generate_alert

class StaticRuleEngine:
    def __init__(self, initiator_only_ports=True, victim_rules=True, protected_prefixes=('192.168.',)):
        # initiator_only_ports: the port-scan rule only counts TCP SYN-only packets (connection
        #   initiations). With False (legacy) it also counts server replies and flags busy servers.
        self.initiator_only_ports = initiator_only_ports
        # victim_rules: fixed per-destination thresholds (the static counterpart of the adaptive
        #   victim rules; same floors, no baseline) so the comparison stays fair.
        self.victim_rules = victim_rules
        self.protected_prefixes = tuple(protected_prefixes)
        self.VICTIM_PPS_THRESHOLD = 400
        self.VICTIM_CONN_THRESHOLD = 32
        self.victim_pkts = defaultdict(int)
        self.victim_syns = defaultdict(int)
        # Naive thresholds
        self.SYN_THRESHOLD = 100    # packets per second
        self.ICMP_THRESHOLD = 100   # packets per second
        self.PORT_SCAN_THRESHOLD = 20 # distinct ports per second
        
        # State tracking
        self.syn_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)
        
        self.current_window_start = 0

    def process_packet(self, features):
        """
        Process a single packet's features through the static rules.
        """
        packet_time = features['timestamp']
        
        # Window management: reset counts if we moved to a new 1-second window
        if packet_time - self.current_window_start >= 1.0:
            self.syn_counts.clear()
            self.icmp_counts.clear()
            self.port_scan_tracker.clear()
            self.victim_pkts.clear()
            self.victim_syns.clear()
            self.current_window_start = packet_time

        src_ip = features['src_ip']
        protocol = features['protocol']
        
        # Rule 1: TCP SYN Flood Detection
        if protocol == 6 and features['tcp_flags'] == 'S':
            self.syn_counts[src_ip] += 1
            if self.syn_counts[src_ip] == self.SYN_THRESHOLD:
                generate_alert(
                    packet_time, "SYN Flood", src_ip, 
                    f"Exceeded {self.SYN_THRESHOLD} SYN packets/sec"
                )

        # Rule 2: ICMP Flood Detection
        # Scapy protocol for ICMP is 1
        elif protocol == 1:
            self.icmp_counts[src_ip] += 1
            if self.icmp_counts[src_ip] == self.ICMP_THRESHOLD:
                generate_alert(
                    packet_time, "ICMP Flood", src_ip, 
                    f"Exceeded {self.ICMP_THRESHOLD} ICMP packets/sec"
                )

        # Rule 4: per-victim floods (all sources combined)
        if self.victim_rules and protocol in (6, 17):
            dst_ip = features['dst_ip']
            if not self.protected_prefixes or dst_ip.startswith(self.protected_prefixes):
                dport = features['dst_port']
                if dport is not None and dport < 1024:
                    self.victim_pkts[dst_ip] += 1
                    if self.victim_pkts[dst_ip] == self.VICTIM_PPS_THRESHOLD:
                        generate_alert(packet_time, "Victim Packet Flood", src_ip,
                                       f"{self.VICTIM_PPS_THRESHOLD} service-port pkts/sec to {dst_ip}")
                if protocol == 6 and features['tcp_flags'] == 'S':
                    self.victim_syns[dst_ip] += 1
                    if self.victim_syns[dst_ip] == self.VICTIM_CONN_THRESHOLD:
                        generate_alert(packet_time, "Victim Connection Flood", src_ip,
                                       f"{self.VICTIM_CONN_THRESHOLD} new connections/sec to {dst_ip}")

        # Rule 3: Port Scan Detection
        if protocol in (6, 17) and features['dst_port'] is not None and (
                not self.initiator_only_ports or (protocol == 6 and features['tcp_flags'] == 'S')):
            self.port_scan_tracker[src_ip].add(features['dst_port'])
            if len(self.port_scan_tracker[src_ip]) == self.PORT_SCAN_THRESHOLD:
                generate_alert(
                    packet_time, "Port Scan", src_ip, 
                    f"Accessed {self.PORT_SCAN_THRESHOLD} distinct ports/sec"
                )

    def flush(self):
        """
        No-op for compatibility with AdaptiveRuleEngine.
        Static rules evaluate immediately, so no buffered state to flush.
        """
        pass
