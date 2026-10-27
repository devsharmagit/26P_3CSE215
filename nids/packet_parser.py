from scapy.all import IP, TCP, UDP, ICMP

def parse_packet(packet):
    """
    Extracts key fields from a scapy packet.
    Returns a dictionary of features or None if it's not an IP packet.
    """
    if not packet.haslayer(IP):
        return None
    
    ip_layer = packet[IP]
    features = {
        'timestamp': float(packet.time),
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'protocol': ip_layer.proto,
        'src_port': None,
        'dst_port': None,
        'tcp_flags': None,
        'length': ip_layer.len if ip_layer.len is not None else len(ip_layer)
    }
    
    # Extract TCP specific fields
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        features['src_port'] = tcp_layer.sport
        features['dst_port'] = tcp_layer.dport
        features['tcp_flags'] = str(tcp_layer.flags)  # e.g. 'S', 'SA' (scapy FSRPAUEC order)
        
    # Extract UDP specific fields
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        features['src_port'] = udp_layer.sport
        features['dst_port'] = udp_layer.dport
        
    # Extract ICMP specific fields (no ports, but protocol helps identify)
    elif packet.haslayer(ICMP):
        features['icmp_type'] = packet[ICMP].type  # ports stay None
        features['icmp_code'] = packet[ICMP].code
        
    return features
