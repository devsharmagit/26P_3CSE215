# Configuration (b) MATCHED, fixed before any result was seen:
# our rejected_probes rule alerts on > 10 failed probes per source in a sliding 60 s window, so Zeek's
# port-scan detector gets the same evidence budget (10 distinct ports) and time window (60 s epoch).
# Address-scan settings and notice suppression stay at their defaults.
redef Scan::port_scan_threshold = 10.0;
redef Scan::port_scan_interval = 60sec;
