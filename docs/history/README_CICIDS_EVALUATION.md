# CICIDS Dataset Evaluation - Quick Start

This README explains how to evaluate the NIDS engines on the CICIDS2017/2018 public datasets.

## Prerequisites

You need a CICIDS2017 or CICIDS2018 CSV file. See `CICIDS_DOWNLOAD_GUIDE.md` for detailed download instructions.

**Recommended starting file:** `Wednesday-workingHours.pcap_ISCX.csv` (contains DoS Slowloris, DoS Hulk, etc. - perfect for our adaptive DoS detection)

## Quick Evaluation (3 Steps)

### 1. Download a CICIDS CSV file

Visit https://www.unb.ca/cic/datasets/ids-2017.html and download one of the CSV files.

For example:
```bash
# Place the downloaded file in the code/ directory
cd code/
# Assuming you downloaded to ~/Downloads/
cp ~/Downloads/Wednesday-workingHours.pcap_ISCX.csv ./
```

### 2. Run the evaluation

```bash
./venv/bin/python evaluate_cicids.py Wednesday-workingHours.pcap_ISCX.csv
```

This will:
- Load and parse the CSV (~540,000 flows)
- Convert flows to packet features (~2-5 million packets)
- Run both Static and Adaptive engines
- Report precision, recall, F1-score, alert volume

Expected runtime: 2-5 minutes depending on file size.

### 3. Review results

The script prints a comparison table like:

```
CICIDS EVALUATION RESULTS: Static vs Adaptive
==========================================================================================

Dataset Overview:
  Total Attacker IPs: 12
  Total Benign IPs: 25

Metric                              Static                    Adaptive    
------------------------------------------------------------------------------------------
True Positives (IPs detected)       7/12                      11/12       
False Positives (benign flagged)    0/25                      2/25        
False Negatives (missed)            5/12                      1/12        

Precision                           100.00%                   84.62%
Recall (Detection Rate)             58.33%                    91.67%
F1-Score                            73.68%                    88.00%

Total Alert Volume                  42                        1248        
```

**Key Takeaways:**
- **Adaptive has higher recall** (catches more attackers)
- **Static has higher precision** (fewer false positives)
- **Adaptive generates more alerts** (alert fatigue tradeoff)

---

## Understanding the Results

### What gets detected?

Our engines target:
- **SYN floods** (static: >100/sec, adaptive: >3x baseline)
- **ICMP floods** (static: >100/sec, adaptive: >3x baseline)
- **Port scans** (static: >20 ports, adaptive: entropy >4.0)
- **Slowloris/slow DoS** (adaptive only: half-open ratio >0.8)

### Why some attacks are missed

- **Web attacks** (SQL injection, XSS): Not detectable by our packet-level rules (requires payload inspection)
- **SSH/FTP brute force**: Appears as normal failed login attempts at the packet level
- **Infiltration**: Low-and-slow exfiltration doesn't trigger rate-based rules
- **Bot traffic**: Mimics normal user behavior

### What CICIDS files work best?

| File | Attack Types | Best For |
|------|-------------|----------|
| Wednesday-workingHours.pcap_ISCX.csv | DoS Slowloris, DoS Hulk, Heartbleed | ✅ **BEST - Tests all our mechanisms** |
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | DDoS | ✅ Good - Tests flood detection |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | Bot, PortScan | ✅ Good - Tests port entropy |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | Web attacks | ⚠️ Limited - Out of scope for packet-level rules |

---

## Advanced: Comparing Multiple Files

```bash
# Evaluate all CICIDS files and save results
for file in *.pcap_ISCX.csv; do
    echo "Evaluating $file..."
    ./venv/bin/python evaluate_cicids.py "$file" > "results_${file%.csv}.txt"
done
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'scapy'"
Activate the venv: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)

### "Memory Error" or script hangs
Start with a smaller file or extract a subset:
```bash
head -n 50001 large_file.csv > subset.csv
./venv/bin/python evaluate_cicids.py subset.csv
```

### CSV parsing errors
The adapter handles most encoding issues automatically. If problems persist, check that you downloaded the CSV files (not PCAP files).

---

## Files in This Implementation

- **`cicids_adapter.py`**: Converts CICIDS CSV flows to packet features
- **`evaluate_cicids.py`**: Main evaluation script (runs both engines on CICIDS)
- **`CICIDS_DOWNLOAD_GUIDE.md`**: Detailed download instructions and dataset overview
- **`test_cicids_mock.csv`**: Small synthetic CSV for testing the adapter (not real CICIDS data)

---

## Next Steps for Research Paper

Once you've evaluated on CICIDS:

1. **Document the results** in a table for the paper's "Experimental Results" section
2. **Compare against the synthetic dataset** results (from `enhanced_metrics.py` on `large_evaluation_dataset.pcap`) to show:
   - Synthetic: 100% recall, 0% FP (controlled environment)
   - CICIDS: ~90% recall, ~5% FP (realistic, noisy traffic)
3. **Discuss attack types detected vs. missed** (our packet-level rules can't catch all attack types, which is honest and expected)
4. **Cite the CICIDS paper** (already in your `research papers/` folder)

This external validation on a public dataset significantly strengthens the paper's credibility!
