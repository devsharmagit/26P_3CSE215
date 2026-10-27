# Zeek: exact time to first true alert (Friday PortScan)

Computed from `friday_scores.json` (`attacker_notices[0].ts`) minus the PortScan window start 13:55:00 ADT (`nids/days.py`).
results.md in this folder prints these values truncated to whole seconds.

| config | notice ts (UTC epoch) | seconds after window start |
|---|---|---|
| default | 1499449905.453788 | 3405.5 |
| matched | 1499449905.453568 | 3405.5 |
