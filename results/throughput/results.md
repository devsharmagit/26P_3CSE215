# Throughput of the rule engine (pure Python)

Reproduce: `python -m experiments.grid wednesday && python -m experiments.derived_tables`
Each run = one configuration over the whole cached capture, 8 runs in parallel on one Apple Silicon laptop;
engine time only (cache reading + engine), excluding the ground-truth pass.

| Day | Configuration | packets | seconds | packets/s |
|---|---|---|---|---|
| friday | count / fixed | 9,915,501 | 42.7 | 232,357 |
| friday | count / adaptive | 9,915,501 | 42.9 | 231,276 |
| friday | behaviour / fixed | 9,915,501 | 49.8 | 199,296 |
| friday | behaviour / adaptive | 9,915,501 | 50.3 | 197,280 |
| friday | all / fixed | 9,915,501 | 53.6 | 184,828 |
| friday | all / adaptive | 9,915,501 | 54.2 | 182,999 |
| friday | all / adaptive, no freeze | 9,915,501 | 54.1 | 183,255 |
| wednesday | count / fixed | 13,705,535 | 57.5 | 238,521 |
| wednesday | count / adaptive | 13,705,535 | 47.5 | 288,244 |
| wednesday | behaviour / fixed | 13,705,535 | 52.5 | 260,852 |
| wednesday | behaviour / adaptive | 13,705,535 | 49.9 | 274,472 |
| wednesday | all / fixed | 13,705,535 | 53.1 | 258,048 |
| wednesday | all / adaptive | 13,705,535 | 52.1 | 263,233 |
| wednesday | all / adaptive, no freeze | 13,705,535 | 52.2 | 262,694 |

Range over these runs: 182,999 to 288,244 packets/s.
