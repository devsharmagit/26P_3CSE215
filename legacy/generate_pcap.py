import time
from scapy.all import IP, TCP, ICMP, wrpcap

packets = []
base_time = time.time()

# 1. SYN Flood Simulation (105 packets in < 1 second)
for i in range(105):
    pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=10000+i, dport=80, flags="S")
    pkt.time = base_time + (i * 0.001)
    packets.append(pkt)

# 2. ICMP Flood Simulation (105 packets in < 1 second)
# Start this after a 2-second gap so it falls in a new window
base_time += 2.0
for i in range(105):
    pkt = IP(src="10.0.0.5", dst="192.168.1.1") / ICMP(type=8)
    pkt.time = base_time + (i * 0.001)
    packets.append(pkt)

# 3. Port Scan Simulation (25 distinct ports in < 1 second)
base_time += 2.0
for i in range(25):
    pkt = IP(src="172.16.0.2", dst="192.168.1.1") / TCP(sport=12345, dport=1+i, flags="S")
    pkt.time = base_time + (i * 0.01)
    packets.append(pkt)

wrpcap("test_phase2.pcap", packets)
print("test_phase2.pcap created with 105 SYN packets, 105 ICMP packets, and 25 port scan packets.")
