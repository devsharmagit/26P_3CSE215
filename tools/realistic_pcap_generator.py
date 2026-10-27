"""
Generate a synthetic capture with benign background traffic and five scripted attackers (192.168.10.201-205: fast and
slow SYN flood, ICMP flood, stealthy and fast port scan). Ground truth: experiments/grid.py, day 'synthetic'
(nids/days.py).

    python tools/realistic_pcap_generator.py     # writes large_evaluation_dataset.pcap in the current folder

The generator is random (no fixed seed), so every run gives a different capture. The tests use the committed
tests/data/large_evaluation_dataset.pcap, and some of them check exact outputs on it: do not replace that file.
"""
import random
import time
from scapy.all import IP, TCP, UDP, ICMP, wrpcap

def generate_large_pcap(filename):
    print(f"Generating LARGE realistic evaluation dataset: {filename}...")
    packets = []
    base_time = time.time()

    # Ground truth
    # Attackers: 192.168.10.201 to 205
    # Benign: 192.168.10.10 to 192.168.10.60
    
    # 1. Generate Benign Background Traffic (spread over 60 seconds)
    print("Generating background traffic (~30,000 packets)...")
    for _ in range(15000):
        src = f"192.168.10.{random.randint(10, 60)}"
        dst = f"8.8.8.{random.randint(1, 10)}"
        sport = random.randint(10000, 60000)
        dport = random.choice([80, 443, 53, 22])
        
        if dport == 53:
            pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
            pkt.time = base_time + random.uniform(0, 60)
            packets.append(pkt)
        else:
            # Simulated handshake
            pkt_syn = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
            pkt_syn.time = base_time + random.uniform(0, 60)
            packets.append(pkt_syn)
            
            pkt_ack = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A")
            pkt_ack.time = pkt_syn.time + random.uniform(0.01, 0.2)
            packets.append(pkt_ack)

    # 2. Fast SYN Flood (Attacker: 192.168.10.201)
    print("Injecting Fast SYN Flood...")
    flood_start = base_time + 10.0
    for i in range(500):
        pkt = IP(src="192.168.10.201", dst="192.168.10.1") / TCP(sport=10000+i, dport=80, flags="S")
        pkt.time = flood_start + (i * 0.001) # Half a second
        packets.append(pkt)

    # 3. Slow SYN Flood (Attacker: 192.168.10.202)
    print("Injecting Slow SYN Flood...")
    slow_flood_start = base_time + 20.0
    for i in range(300):
        pkt = IP(src="192.168.10.202", dst="192.168.10.1") / TCP(sport=20000+i, dport=80, flags="S")
        pkt.time = slow_flood_start + (i * 0.05) # Over 15 seconds
        packets.append(pkt)

    # 4. ICMP Flood (Attacker: 192.168.10.203)
    print("Injecting ICMP Flood...")
    icmp_start = base_time + 30.0
    for i in range(600):
        pkt = IP(src="192.168.10.203", dst="192.168.10.1") / ICMP(type=8)
        pkt.time = icmp_start + (i * 0.001)
        packets.append(pkt)

    # 5. Stealthy Port Scan (Attacker: 192.168.10.204)
    print("Injecting Stealthy Port Scan...")
    stealth_start = base_time + 40.0
    for i in range(150):
        pkt = IP(src="192.168.10.204", dst="192.168.10.1") / TCP(sport=50000, dport=1+i, flags="S")
        pkt.time = stealth_start + (i * 0.1) # Over 15 seconds
        packets.append(pkt)

    # 6. Fast Port Scan (Attacker: 192.168.10.205)
    print("Injecting Fast Port Scan...")
    fast_scan_start = base_time + 55.0
    for i in range(100):
        pkt = IP(src="192.168.10.205", dst="192.168.10.1") / TCP(sport=60000, dport=1+i, flags="S")
        pkt.time = fast_scan_start + (i * 0.005) # Half a second
        packets.append(pkt)

    print("Sorting packets chronologically...")
    packets.sort(key=lambda x: x.time)
    
    print(f"Writing PCAP...")
    wrpcap(filename, packets)
    print(f"Done. Wrote {len(packets)} packets to {filename}.")

if __name__ == "__main__":
    generate_large_pcap("large_evaluation_dataset.pcap")
