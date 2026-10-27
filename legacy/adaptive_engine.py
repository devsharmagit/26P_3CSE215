import math
from collections import defaultdict
from nids.alerts import generate_alert

class AdaptiveRuleEngine:
    def __init__(self, initiator_only_ports=True, baseline_freeze=True, victim_rules=True,
                 protected_prefixes=('192.168.',), enabled_rules=None):
        # enabled_rules: subset of {'syn','icmp','entropy','half_open','victim'} (None = all); used for ablations.
        self.enabled_rules = set(enabled_rules) if enabled_rules is not None else {'syn', 'icmp', 'entropy', 'half_open', 'victim'}
        # initiator_only_ports: destination ports are only counted for connection-initiating packets
        #   (TCP SYN without ACK). With False (legacy), servers replying to many clients (DNS/web
        #   servers) look like port scanners.
        self.initiator_only_ports = initiator_only_ports
        # baseline_freeze: stop updating a baseline while it is under alert (and for a cool-down
        #   afterwards). With False (legacy), a sustained flood is absorbed into the EMA and the
        #   threshold climbs until the attack stops alerting (baseline poisoning).
        self.baseline_freeze = baseline_freeze
        self.freeze_seconds = 60.0
        self.frozen_until = {}  # baseline key -> time before which the EMA is not updated
        # victim_rules: per-destination flood rules (packet rate to service ports, new-connection
        #   rate), counted over traffic from ALL sources, so distributed floods are visible.
        #   Only destinations inside protected_prefixes are tracked (empty tuple = all).
        self.victim_rules = victim_rules and 'victim' in self.enabled_rules
        self.protected_prefixes = tuple(protected_prefixes)
        self.VICTIM_PPS_MULTIPLIER = 3.0
        self.MIN_VICTIM_PPS = 400          # service-port packets/sec to one protected host
        self.VICTIM_CONN_MULTIPLIER = 3.0
        self.MIN_VICTIM_CONN_RATE = 32     # new (SYN-only) connections/sec to one protected host (benign max 38; 2 s/day above 32)
        self.current_victim_pkts = defaultdict(int)
        self.current_victim_syns = defaultdict(int)
        self.current_victim_srcs = defaultdict(lambda: defaultdict(int))
        self.historical_victim_pps = defaultdict(float)
        self.historical_victim_conn = defaultdict(float)
        # Baseline multipliers and minimums
        self.SYN_MULTIPLIER = 3.0
        self.MIN_SYN_THRESHOLD = 50
        
        self.ICMP_MULTIPLIER = 3.0
        self.MIN_ICMP_THRESHOLD = 50
        
        # Entropy threshold for port scans
        self.ENTROPY_THRESHOLD = 4.0
        self.MIN_PORTS_FOR_ENTROPY = 10
        
        # Half-open ratio settings
        self.HALF_OPEN_RATIO_THRESHOLD = 0.8
        self.MIN_CONNECTIONS_FOR_RATIO = 20

        # State tracking (Window-based)
        self.current_window_start = 0
        self.latest_time = 0.0  # timestamp of the packet that triggered the current rollover
        self.window_duration = 1.0  # seconds
        
        # Current window counts
        self.current_syn_counts = defaultdict(int)
        self.current_icmp_counts = defaultdict(int)
        
        # Historical moving averages (EMA) for adaptive thresholds
        self.historical_syn_avg = defaultdict(float)
        self.historical_icmp_avg = defaultdict(float)
        self.alpha = 0.2  # EMA smoothing factor
        
        # Port scan tracking with decay
        self.port_frequencies = defaultdict(lambda: defaultdict(int))
        self.port_decay_factor = 0.5  # Halve port counts each window
        
        # Connection tracking for Half-Open connections
        # Tracks state of (src_ip, dst_ip, src_port, dst_port): True if SYN-ACK/ACK seen, False if only SYN
        self.connections = {}
        self.connection_timestamps = {}  # Track when each connection was last seen
        self.connection_timeout = 30.0  # Prune connections older than 30 seconds
        # We track connection tuples per src_ip to easily compute ratios
        self.src_connections = defaultdict(set)

    def process_packet(self, features):
        packet_time = features['timestamp']
        src_ip = features['src_ip']
        protocol = features['protocol']
        
        # Check if we moved to a new time window
        if packet_time - self.current_window_start >= self.window_duration:
            self.latest_time = packet_time
            self._evaluate_and_rollover_window()
            self.current_window_start = packet_time

        # Per-victim counters (all sources combined)
        if self.victim_rules and protocol in (6, 17):
            dst_ip = features['dst_ip']
            dport = features['dst_port']
            if (not self.protected_prefixes or dst_ip.startswith(self.protected_prefixes)):
                if dport is not None and dport < 1024:
                    self.current_victim_pkts[dst_ip] += 1
                    self.current_victim_srcs[dst_ip][src_ip] += 1
                flags = features['tcp_flags']
                if protocol == 6 and flags and 'S' in flags and 'A' not in flags:
                    self.current_victim_syns[dst_ip] += 1

        # TCP Logic (SYN / ACK)
        if protocol == 6:
            tcp_flags = features['tcp_flags']
            if tcp_flags:
                # 1. Track SYN packets for flood detection
                if 'S' in tcp_flags and 'A' not in tcp_flags:
                    self.current_syn_counts[src_ip] += 1
                    
                    # Track half-open connections
                    if features['dst_port'] is not None and features['src_port'] is not None:
                        conn_tuple = (src_ip, features['dst_ip'], features['src_port'], features['dst_port'])
                        if conn_tuple not in self.connections:
                            self.connections[conn_tuple] = False  # Not fully open
                            self.connection_timestamps[conn_tuple] = packet_time
                            self.src_connections[src_ip].add(conn_tuple)
                            
                # 2. Track ACKs to complete half-open connections
                elif 'A' in tcp_flags:
                    # In a real scenario we need bidirectional tracking.
                    # If the source sends an ACK, the connection is established.
                    # Or if we see a SYN-ACK from the destination, etc.
                    # For simplicity, if this src_ip sends an ACK, we mark it established.
                    if features['dst_port'] is not None and features['src_port'] is not None:
                        conn_tuple = (src_ip, features['dst_ip'], features['src_port'], features['dst_port'])
                        if conn_tuple in self.connections:
                            self.connections[conn_tuple] = True
                            self.connection_timestamps[conn_tuple] = packet_time

            # 3. Track ports for Entropy-based Port Scan detection
            is_initiator = bool(tcp_flags) and 'S' in tcp_flags and 'A' not in tcp_flags
            if features['dst_port'] is not None and (is_initiator or not self.initiator_only_ports):
                self.port_frequencies[src_ip][features['dst_port']] += 1

        # ICMP Logic
        elif protocol == 1:
            self.current_icmp_counts[src_ip] += 1

    def _update_baseline(self, store, key, count, alerted):
        """EMA update; with baseline_freeze an alerting key is frozen for freeze_seconds."""
        if self.baseline_freeze:
            now = self.current_window_start
            if alerted:
                self.frozen_until[(id(store), key)] = now + self.freeze_seconds
                return
            if now < self.frozen_until.get((id(store), key), 0):
                return
        store[key] = (self.alpha * count) + ((1 - self.alpha) * store[key])

    def _evaluate_and_rollover_window(self):
        """
        Evaluate adaptive rules at the end of a window and update historical baselines.
        """
        # Evaluate SYN Floods
        for src_ip, count in (self.current_syn_counts.items() if 'syn' in self.enabled_rules else ()):
            avg = self.historical_syn_avg[src_ip]
            threshold = max(self.MIN_SYN_THRESHOLD, avg * self.SYN_MULTIPLIER)
            
            alerted = count > threshold
            if alerted:
                generate_alert(self.current_window_start, "Adaptive SYN Flood", src_ip, f"Sent {count} SYNs (Avg: {avg:.1f}, Threshold: {threshold:.1f})")
            
            # Update EMA (Time-Weighted Window concept for baselines)
            self._update_baseline(self.historical_syn_avg, src_ip, count, alerted)
            
        # Evaluate ICMP Floods
        for src_ip, count in (self.current_icmp_counts.items() if 'icmp' in self.enabled_rules else ()):
            avg = self.historical_icmp_avg[src_ip]
            threshold = max(self.MIN_ICMP_THRESHOLD, avg * self.ICMP_MULTIPLIER)
            
            alerted = count > threshold
            if alerted:
                generate_alert(self.current_window_start, "Adaptive ICMP Flood", src_ip, f"Sent {count} ICMPs (Avg: {avg:.1f}, Threshold: {threshold:.1f})")
            
            self._update_baseline(self.historical_icmp_avg, src_ip, count, alerted)

        # Evaluate per-victim floods (all sources combined)
        if self.victim_rules:
            self._evaluate_victims()

        # Evaluate Port Scan (Entropy)
        for src_ip, port_counts in (self.port_frequencies.items() if 'entropy' in self.enabled_rules else ()):
            total_accesses = sum(port_counts.values())
            num_distinct_ports = len(port_counts)
            
            if num_distinct_ports >= self.MIN_PORTS_FOR_ENTROPY:
                entropy = 0.0
                for port, count in port_counts.items():
                    p = count / total_accesses
                    entropy -= p * math.log2(p)
                
                if entropy > self.ENTROPY_THRESHOLD:
                    generate_alert(self.current_window_start, "Entropy Port Scan", src_ip, f"High port entropy: {entropy:.2f} across {num_distinct_ports} ports")

        # Evaluate Half-Open Connections (Slowloris/Stealth DoS)
        for src_ip, conns in (self.src_connections.items() if 'half_open' in self.enabled_rules else ()):
            total_conns = len(conns)
            if total_conns >= self.MIN_CONNECTIONS_FOR_RATIO:
                half_open_count = sum(1 for c in conns if not self.connections[c])
                ratio = half_open_count / total_conns
                
                if ratio >= self.HALF_OPEN_RATIO_THRESHOLD:
                    generate_alert(self.current_window_start, "Half-Open DoS", src_ip, f"Ratio of half-open connections is {ratio:.2f} ({half_open_count}/{total_conns})")

        # Reset current window state
        self.current_syn_counts.clear()
        self.current_icmp_counts.clear()
        self.current_victim_pkts.clear()
        self.current_victim_syns.clear()
        self.current_victim_srcs.clear()
        
        # Apply exponential decay to port frequencies, once per elapsed window (a quiet gap decays more)
        elapsed_windows = max(1, int((self.latest_time - self.current_window_start) / self.window_duration))
        decay = self.port_decay_factor ** min(elapsed_windows, 64)
        for src_ip in list(self.port_frequencies.keys()):
            for port in list(self.port_frequencies[src_ip].keys()):
                self.port_frequencies[src_ip][port] *= decay
                # Remove ports with negligible counts
                if self.port_frequencies[src_ip][port] < 0.5:
                    del self.port_frequencies[src_ip][port]
            # Remove source IPs with no ports left
            if not self.port_frequencies[src_ip]:
                del self.port_frequencies[src_ip]
        
        # Prune stale connections older than timeout
        current_time = max(self.current_window_start, self.latest_time)
        stale_connections = [conn for conn, timestamp in self.connection_timestamps.items()
                            if current_time - timestamp > self.connection_timeout]
        for conn in stale_connections:
            if conn in self.connections:
                del self.connections[conn]
            del self.connection_timestamps[conn]
            # Remove from src_connections tracking
            src_ip = conn[0]
            if src_ip in self.src_connections:
                self.src_connections[src_ip].discard(conn)
                if not self.src_connections[src_ip]:
                    del self.src_connections[src_ip]

    def _evaluate_victims(self):
        """Adaptive per-destination rules. The alert is attributed to the dominant source."""
        for dst_ip in set(self.current_victim_pkts) | set(self.current_victim_syns):
            for rule, counts, store, mult, floor, unit in (
                    ("Victim Packet Flood", self.current_victim_pkts, self.historical_victim_pps,
                     self.VICTIM_PPS_MULTIPLIER, self.MIN_VICTIM_PPS, "service-port pkts"),
                    ("Victim Connection Flood", self.current_victim_syns, self.historical_victim_conn,
                     self.VICTIM_CONN_MULTIPLIER, self.MIN_VICTIM_CONN_RATE, "new connections")):
                count = counts.get(dst_ip, 0)
                avg = store[dst_ip]
                threshold = max(floor, avg * mult)
                alerted = count > threshold
                if alerted:
                    srcs = self.current_victim_srcs.get(dst_ip)
                    if srcs:
                        top = max(srcs, key=srcs.get)
                        share = srcs[top] / sum(srcs.values())
                    else:
                        top, share = "multiple", 0.0
                    generate_alert(self.current_window_start, rule, top,
                                   f"{count} {unit}/s to {dst_ip} (Avg: {avg:.1f}, Threshold: {threshold:.1f}, top source share: {share:.0%})")
                self._update_baseline(store, dst_ip, count, alerted)
        # forget victims with no traffic to keep state bounded
        for store in (self.historical_victim_pps, self.historical_victim_conn):
            for k in [k for k, v in store.items() if v < 0.01 and k not in self.current_victim_pkts and k not in self.current_victim_syns]:
                del store[k]

    def flush(self):
        """
        Evaluate any remaining packets in the current window when capture ends.
        """
        self._evaluate_and_rollover_window()
