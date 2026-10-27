# Transparent Rule-Based Network Intrusion Detection and Packet Analyzer

A packet-level network intrusion detection system (NIDS) whose detection rules are plain data. Every alert
explains itself: it lists each rule that fired, the measured value, the threshold and, for adaptive rules, the
learned baseline. The same engine is used for a controlled study of **what** a rule should measure versus **how** its
threshold should be set, evaluated on the raw CICIDS2017 captures.

Paper: *What a Rule Measures Matters More Than How Its Threshold Is Set: Port-Scan Evidence from a Transparent
Rule-Based IDS on CICIDS2017* — Surinder Pal Singh, Dev Sharma, Megha, Vaibhav Sinha, School of Computer Science and
Engineering, IILM University, Greater Noida, India.

## Features

- **Rules as data** (`config/rules.yaml`): each rule has a measure, a scope (sending host or protected host), a kind
  (count or behaviour), a threshold that is *fixed* or *per-host adaptive* (moving-average baseline with a floor and an
  attack freeze), an optional sliding window and a weight. Changing a threshold or a policy needs no code change.
- **Eight built-in measures**: SYN rate, ICMP rate, distinct destination ports, packets and new connections per
  protected host (count measures); half-open connection share, destination-port entropy, and probes refused by
  protected hosts (behaviour measures).
- **Transparent score**: per host and second, the sum of the weights of the rules that fired, with the evidence for
  every point, e.g. `score 2 = rejected_probes(+1): 14 > 10 [fixed] + half_open(+1): 1.00 >= 0.80 [fixed]`.
- **Packet analyzer**: protocol mix, top talkers and services, a timeline with detections and an incident list in a
  self-contained HTML report.
- **Fast capture reader** for pcap/pcapng (no scapy needed) with an optional binary cache; live capture with scapy.
- **Reproducible experiments**: every table and figure of the paper is produced by one command, with pre-registered
  analysis plans for the controls.

## Repository layout

```
.
├── main.py                 command-line interface: rules, detect, analyze, live
├── config/
│   ├── rules.yaml          the rule set used throughout (format documented at the top of the file)
│   └── legacy_rules.yaml   the Phase-1 adaptive engine expressed as a rule file
├── nids/                   core library
│   ├── engine.py           rule engine: measures, fixed/adaptive thresholds, score and evidence
│   ├── rule_set.py         rule-file loader and validator
│   ├── pcapng_reader.py    fast pcap/pcapng reader and cache builder
│   ├── packet_parser.py    packet parsing for live capture (scapy)
│   ├── analyzer.py         traffic statistics and HTML report
│   ├── alerts.py           alert logging
│   ├── days.py             CICIDS2017 ground truth (attacker, victim, attack windows, segments)
│   └── paths.py            where config, data and results live
├── experiments/            scripts that produce the paper's results (run as python -m experiments.<name>)
├── baselines/              Zeek (scan.zeek) and Suricata (ET Open, custom rules) baselines and their scoring
├── tests/                  unit and regression tests (+ a small synthetic capture in tests/data/)
├── tools/                  generator of the synthetic test capture
├── results/                every results file behind the paper (see results/README.md)
├── docs/                   pre-registered analysis plans, notes from earlier phases
├── legacy/                 Phase-1 engines and scripts, kept for reference (see legacy/README.md)
├── data/                   put the CICIDS2017 captures here (not in the repository; see data/README.md)
├── reproduce.sh            one command per paper table / figure
└── requirements.txt        pinned Python dependencies
```

## Installation

Python 3.10 or newer (developed and tested with Python 3.14 and 3.15 on macOS).

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python -m pytest -q            # 53 tests, about 3 s, no dataset needed
```

All commands below are run from the repository root with the virtual environment's Python
(`source venv/bin/activate`, or prefix with `./venv/bin/`).

## Quick start (no dataset needed)

```bash
python main.py rules                                                  # the rules, in plain words
python main.py detect -f tests/data/large_evaluation_dataset.pcap     # scored detections with evidence
python main.py analyze -f tests/data/large_evaluation_dataset.pcap    # HTML report -> report/<name>/report.html
```

Try a change without touching code: in `config/rules.yaml` set `policy: adaptive` on a rule (or change a `value`) and
run `detect` again. Other options: `-r <rule file>`, `--policy fixed|adaptive`, `--min-score k`, `-o detections.jsonl`;
`python main.py <command> -h` lists them all. Live capture: `sudo python main.py live -i <interface>`.

## Using CICIDS2017

Download the Friday and Wednesday captures from the official CIC page and put them in `data/` (or set `NIDS_DATA`);
`data/README.md` has the links, file names and checksums. Then, for example:

```bash
python main.py analyze -f data/Friday-WorkingHours.pcap --truth friday   # report with the attack windows shaded
python -m experiments.grid friday                                        # the main grid on Friday
```

## Reproducing the paper

`./reproduce.sh <item>` runs the command(s) for one item; results are written to `results/`.

| Paper item | Command | Main script(s) | Time (8 cores) |
|---|---|---|---|
| Table I, rule set | `./reproduce.sh table1` | `main.py rules` | seconds |
| Table II, main grid (Friday, Wednesday) | `./reproduce.sh table2` | `experiments/grid.py` | about 2 min per day |
| Table III, matched windows | `./reproduce.sh table3` | `experiments/window_matching.py` | about 4 min |
| Table IV, bootstrap intervals | `./reproduce.sh table4` | `experiments/ci_per_second.py`, `bootstrap_ci.py` | about 1–2 min |
| Table V, Zeek and Suricata | `./reproduce.sh table5` | `baselines/`, `experiments/derived_tables.py`, `ttd_check.py` | needs Zeek 9 and Suricata 8 |
| Table VI, Wednesday per attack | `./reproduce.sh table6` | `experiments/derived_tables.py`, `slow_dos_check.py` | about 3 min |
| Strict scoring (Section V-A) | `./reproduce.sh strict` | `experiments/scoring_check.py` | about 2 min |
| Fig. 1, sensitivity sweep | `./reproduce.sh fig1` | `experiments/sensitivity.py`, `latex_figures.py` | about 5 min |
| Fig. 2, DDoS trace | `./reproduce.sh fig2` | `experiments/paper_figures.py`, `latex_figures.py` | about 2 min |

Order: `table2` first (the other items compare against its results). `./reproduce.sh all` runs everything except the
Zeek/Suricata baselines. Pre-registered plans for the sweep, the window control and the bootstrap are in
`docs/preregistration/`.

## Tests

`python -m pytest -q` runs 53 tests: rule-file validation, every measure, fixed and adaptive thresholds, the freeze,
score and evidence, sliding windows, the capture reader and cache, the HTML report, the bootstrap on toy data, a
fingerprint check that the default rule set's output is unchanged, and an equivalence test against the Phase-1
adaptive engine.

## Results

`results/README.md` maps every table and figure of the paper to its results file. Headline: on the CICIDS2017 Friday
port scan, changing what a rule measures raised F1 from 38.3% to 91.7% (behaviour rules still won with matched 1 s and
60 s windows), while per-host adaptive thresholds showed no detectable gain in a 66-setting sweep; without the freeze,
the adaptive baseline learned the DDoS (F1 87.1% → 11.6%).

## Project history

`legacy/` holds the Phase-1 static and adaptive engines and their evaluation scripts; `docs/history/` holds notes
from that phase. The current engine reproduces the Phase-1 adaptive engine exactly with `config/legacy_rules.yaml`.

## Citation

See `CITATION.cff`.
