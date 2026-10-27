# Rule-Based Network Intrusion & Packet Analyzer

This document outlines the step-by-step tasks required to implement Proposal A: an Adaptive-Threshold Rule Engine for DoS and Port-Scan detection.

## Phase 1: Packet Capture & Parsing Pipeline
- [x] Set up the Python project environment and dependencies (`scapy`).
- [x] Create a basic packet sniffer script to read live traffic or `.pcap` files.
- [x] Extract key fields from the packets (Source IP, Destination IP, Ports, TCP Flags, Protocol).

## Phase 2: Static Rule Engine (Baseline)
- [x] Implement a naive threshold for SYN packets (e.g., alert if > 100 SYN packets/sec from a single IP).
- [x] Implement a naive threshold for ICMP floods (e.g., alert if > 100 ICMP echo requests/sec).
- [x] Implement a naive port-scan detection rule (e.g., alert if connection attempts to > 20 distinct ports within a time window).
- [x] Test the static rules against lab-generated traffic (`hping3`, `nmap`) or small CICIDS2017 pcap files.

## Phase 3: Adaptive Mechanisms (The Core Novelty)
- [x] **Adaptive Thresholding:** Implement logic to compute a short baseline of normal packet rates (PPS/SYN rate) per host. Update thresholds dynamically.
- [x] **Half-Open Connection Ratio:** Track uncompleted TCP handshakes (SYN sent without ACK response) over time to detect Slowloris and low-and-slow DoS attacks.
- [x] **Port Entropy:** Calculate the entropy of destination ports accessed by a single source IP to detect stealthy/distributed port scans.
- [x] **Time-Weighted Window:** Implemented exponential decay (0.5 factor per window) for port frequencies and connection pruning (30s timeout) to bound memory growth while preserving slow-accumulation detection.

## Phase 4: Alerting & Logging
- [x] Create an alerting module that formats and outputs triggered rules to a log file or console.
- [x] Include detailed information in alerts (Timestamp, Source IP, Triggered Rule, Metric Value vs Threshold).

## Phase 5: Evaluation
- [x] Run the complete adaptive NIDS against synthetic realistic dataset (large_evaluation_dataset.pcap).
- [x] Compare the false-positive rate and detection rate of the adaptive rules against the static baseline rules (benchmark.py).
- [x] Implemented enhanced metrics (precision, recall, F1, time-to-detection, alert volume) in enhanced_metrics.py.
- [ ] **TODO:** Run evaluation against public CICIDS2017/2018 dataset for external validation.

## Phase 6: Rules as data, analyzer, reframed study (2026-10-21)
- [x] Rule file `rules.yaml` + loader/validator `rule_set.py`; one engine `engine.py` for every rule (fixed or adaptive threshold per rule).
- [x] `engine.py` reproduces `adaptive_engine.py` exactly when given `legacy_rules.yaml` (Friday: 3,617/3,617 alerts).
- [x] Transparent score: per source and second, sum of weights of the rules that fired, with evidence for every point.
- [x] New behaviour rule `rejected_probes` (time window 60 s): catches the slow Nmap phases (scan recall 45% -> 84%).
- [x] Fast reader now reads classic pcap too, records packet length and ICMP type/code (cache v2, old caches still readable).
- [x] `main.py` subcommands: `rules`, `detect`, `analyze` (HTML report: protocols, talkers, services, timeline, incidents), `live`.
- [x] `experiments.py`: {count, behaviour, all} x {fixed, adaptive}, no-freeze, single rules, minus-one, score filter, sensitivity.
- [x] `days.py` ground truth for Friday, synthetic and Wednesday; `explore_day.py` to verify Wednesday windows.
- [ ] **Wednesday PCAP** (held-out day): download from CIC (registration form), then `explore_day.py wednesday`, `experiments.py wednesday`.
