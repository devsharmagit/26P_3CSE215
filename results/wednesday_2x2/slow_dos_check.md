# Slow-DoS check (Wednesday, attacker 172.16.0.1 -> 192.168.10.50)

Reproduce: `python -m experiments.slow_dos_check`. A connection = (source port, destination port) opened by a
SYN-only packet inside the window; completed = an ACK from the attacker on the same ports was seen afterwards.

| Attack | connections opened | completed handshake | median SYN/s (seconds with a SYN) | max SYN/s |
|---|---|---|---|---|
| DoS slowloris | 3,894 | 57.5 % | 6 | 158 |
| DoS Slowhttptest | 4,217 | 33.5 % | 1 | 569 |
| DoS Hulk | 14,108 | 100.0 % | 290 | 1291 |
| DoS GoldenEye | 7,496 | 100.0 % | 16 | 281 |
