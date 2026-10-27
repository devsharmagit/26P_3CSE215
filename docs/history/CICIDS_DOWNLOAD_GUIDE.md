# CICIDS2017/2018 Dataset Download Guide

This guide explains how to obtain the CICIDS2017 or CICIDS2018 datasets for evaluation.

## Option 1: CICIDS2017 (Recommended)

**Dataset Page:** https://www.unb.ca/cic/datasets/ids-2017.html

### Download Instructions:

1. Visit the dataset page above
2. Scroll to "Download" section
3. Download the CSV files (not PCAP, as they're very large)

### Recommended Files for Testing:

Start with one of these smaller files for initial testing:

- **Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv** (~225 MB)
  - Contains: DDoS attacks, good for testing flood detection
  - Direct link: https://www.unb.ca/cic/datasets/ids-2017.html

- **Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv** (~20 MB)
  - Contains: Web attacks, SQL injection, XSS
  
- **Wednesday-workingHours.pcap_ISCX.csv** (~460 MB)
  - Contains: DoS GoldenEye, DoS Slowloris, DoS Slowhttptest, DoS Hulk
  - **Excellent for testing our adaptive DoS detection mechanisms**

### Full Dataset Structure:

```
CICIDS2017/
├── Monday-WorkingHours.pcap_ISCX.csv (benign traffic only)
├── Tuesday-WorkingHours.pcap_ISCX.csv (FTP-Patator, SSH-Patator)
├── Wednesday-workingHours.pcap_ISCX.csv (DoS attacks - RECOMMENDED)
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv (Bot, PortScan)
└── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (DDoS - RECOMMENDED)
```

---

## Option 2: CICIDS2018

**Dataset Page:** https://www.unb.ca/cic/datasets/ids-2018.html

The CICIDS2018 (CSE-CIC-IDS2018) dataset is larger and more diverse but follows a similar format.

---

## Quick Start After Download

### 1. Place the CSV file in the `code/` directory

```bash
cd code/
# Assuming you downloaded the file to ~/Downloads/
cp ~/Downloads/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv ./
```

### 2. Test the adapter

```bash
./venv/bin/python cicids_adapter.py Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

This will load the dataset and print statistics (number of flows, attacker IPs, benign IPs, attack types).

### 3. Run full evaluation

```bash
./venv/bin/python evaluate_cicids.py Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

This will:
- Load the CICIDS CSV
- Convert flows to packet features
- Run both StaticRuleEngine and AdaptiveRuleEngine
- Print precision, recall, F1-score, and alert volume comparison

---

## Expected Output

You should see output like:

```
======================================================================
CICIDS Dataset Statistics
======================================================================
Total Flows: 225745
Benign Hosts: 18
Attacker Hosts: 5

Attack Type Distribution:
  DDoS: 5 hosts
======================================================================

Running StaticRuleEngine on CICIDS dataset...
  Processed 10000/150000 packets...
  Processed 20000/150000 packets...
  ...
  Total alerts generated: 127

Running AdaptiveRuleEngine on CICIDS dataset...
  ...
  Total alerts generated: 843

======================================================================
CICIDS EVALUATION RESULTS: Static vs Adaptive
======================================================================

Metric                              Static                    Adaptive    
----------------------------------------------------------------------------------
True Positives (IPs detected)       3/5                       5/5
False Positives (benign flagged)    0/18                      1/18
False Negatives (missed)            2/5                       0/5

Precision                           100.00%                   83.33%
Recall (Detection Rate)             60.00%                    100.00%
F1-Score                            75.00%                    90.91%

Total Alert Volume                  127                       843
```

---

## Alternative: Use Smaller Sample Files

If you want to test quickly without downloading large files, you can:

1. Download a small sample from Kaggle (search "CICIDS2017")
2. Use only the first N rows of a full CSV:

```bash
# Extract first 10000 rows for quick testing
head -n 10001 Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv > sample_cicids.csv
./venv/bin/python evaluate_cicids.py sample_cicids.csv
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'scapy'"

Activate the virtual environment first:

```bash
cd code/
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate     # On Windows
python evaluate_cicids.py <csv_file>
```

### CSV encoding errors

If you get encoding errors, the adapter automatically handles this with `errors='ignore'`. 
If problems persist, try:

```bash
iconv -f ISO-8859-1 -t UTF-8 input.csv > output_utf8.csv
```

### Memory issues with large CSVs

Start with a smaller file (Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv is only ~20 MB)
or use the head command to extract a subset as shown above.

---

## Citation

If you use CICIDS2017/2018 in your research paper, cite:

**CICIDS2017:**
```
Sharafaldin, I., Lashkari, A.H., & Ghorbani, A.A. (2018). 
Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. 
In Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP).
```

**CICIDS2018:**
```
Sharafaldin, I., Lashkari, A. H., Hakak, S., & Ghorbani, A. A. (2019). 
Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy. 
In 2019 International Carnahan Conference on Security Technology (ICCST) (pp. 1-8). IEEE.
```

(Both papers are already in your `research papers/` folder!)
