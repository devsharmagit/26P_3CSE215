# Friday scan phases: attacker -> victim traffic by protocol

Reproduce: `python -m experiments.scan_phase_check`. Times ADT. Counts are packets 172.16.0.1 -> 192.168.10.50.

| phase | packets by protocol | distinct TCP ports in SYN-only packets |
|---|---|---|
| 13:55-14:17 | TCP 857 | 5 |
| 14:17-14:21 | UDP 39 | 0 |
| 14:51-14:57 | TCP 140,712, ICMP 4 | 998 |
| 15:08-15:11 | TCP 11,579 | 999 |
| 15:11-15:16 | UDP 228, IP proto 2 60, IP proto 132 60, ICMP 31 | 0 |
| 15:16-15:29 | TCP 9,474, ICMP 2, IP proto 2 2, IP proto 132 2, UDP 1 | 999 |
