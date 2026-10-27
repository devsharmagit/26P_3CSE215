# Rule-Based Adaptive Network Intrusion Detection System (NIDS)
**Implementation Summary (Phases 1 - 5)**

This document serves as a comprehensive summary of the Python NIDS we built to fulfill Proposal A of the Phase 1 Project Report. It details the architecture, the novel adaptive mechanisms, and the evaluation results.

---

## 1. Project Architecture

We constructed a modular, lightweight packet analyzer using Python and the `scapy` library. The system is designed to run on resource-constrained edge devices without the overhead of heavy Machine Learning models.

### Key Modules:
*   `packet_parser.py`: Extracts critical header information (Source IP, Destination IP, Ports, TCP Flags, Protocol) and the forensic timestamp from raw packets.
*   `adaptive_engine.py`: The mathematical core of the system. It tracks connection states, calculates historical moving averages, and measures port entropy.
*   `alerts.py`: A professional logging module that outputs structured, SIEM-compatible alerts to the console and to `alerts.log`.
*   `main.py`: The entry point that bridges packet capture (`scapy.sniff`) with the parsing and rule engine pipelines.

---

## 2. Core Novelty: Adaptive Mechanisms (Phase 3)

Traditional signature-based NIDS (like default Snort) suffer from "Alert Fatigue" (Vermeer 2022) due to static thresholds, and they often miss stealthy "Low-and-Slow" attacks. We addressed these documented weaknesses with three adaptive mathematical models:

### A. Adaptive Thresholds (Exponential Moving Average)
Instead of alerting when an IP sends `> 100` SYN packets in a second, the engine maintains an EMA of the host's normal traffic rate. 
*   **How it works:** A threshold multiplier is applied to the historical average. A sudden burst (SYN Flood or ICMP Flood) breaks the dynamic threshold, triggering an alert. Normal traffic growth over time is absorbed into the baseline, preventing false positives.

### B. Half-Open TCP Ratio (Slowloris/Stealth DoS Detection)
Attackers performing Slowloris or stealth DoS attacks intentionally send packets slowly to evade rate-limits, but they leave TCP handshakes incomplete (sending a SYN, but never acknowledging the SYN-ACK).
*   **How it works:** The engine tracks the state of every TCP connection. It calculates the ratio of incomplete handshakes vs. total connection attempts per Source IP. If the ratio reaches 100% (or above our 0.8 threshold), it flags the IP for stealth DoS.

### C. Shannon Port Entropy (Distributed Port Scan Detection)
Stealthy port scans attempt to connect to a wide variety of ports slowly over time to avoid static port-count thresholds.
*   **How it works:** We calculate the Shannon Entropy of the destination ports accessed by a single IP. Uniform distribution across many ports yields a high mathematical entropy score (e.g., `> 4.0`), mathematically exposing the scan regardless of the speed at which it occurs.

---

## 3. Professional Alerting & Logging (Phase 4)

We implemented an enterprise-grade logging format that is highly "explainable" (addressing the "black-box" criticism of ML models).

**Example Log Output:**
`2026-09-18 22:41:16 | WARNING | [SRC: 192.168.10.50] [RULE: Adaptive SYN Flood] [TIME: 2026-09-18 22:41:16] -> Sent 174 SYNs (Avg: 5.2, Threshold: 50.0)`

*   **Explainable Logic:** The alert includes the mathematical context (`Avg: 5.2, Threshold: 50.0`) so analysts know *why* it triggered.
*   **Forensic Timestamps:** The `[TIME: ...]` field reflects the exact packet capture time embedded in the `.pcap` file, ensuring accurate historical analysis.

---

## 4. Evaluation & Results (Phase 5)

To prove the efficacy of the system against realistic, large-scale traffic (simulating CICIDS2017 conditions), we generated a 60-second `.pcap` dataset containing ~28,000 packets.

**Dataset Composition:**
*   **51 Benign Hosts:** Generating standard background traffic.
*   **5 Malicious Attackers:** Executing Fast SYN Floods, Slow SYN Floods, ICMP Floods, Stealth Port Scans, and Fast Port Scans.

**Evaluation Results:**
```text
--- Evaluation Results ---
Total Packets Processed: 27,905
True Attackers Detected: 5/5
False Positives: 0/51 benign hosts flagged
-------------------------
Detection Rate (Recall): 100.00%
False Positive Rate:     0.00%
```

**Conclusion:** The adaptive rules perfectly separated normal background traffic from malicious attacks, catching both aggressive bursts and slow, stealthy evasion techniques without generating a single false positive.
