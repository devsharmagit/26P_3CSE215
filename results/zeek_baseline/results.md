# Zeek port-scan baseline (task T03): Friday, CICIDS2017

Status: **done**. Zeek ran on the full Friday capture with both pre-registered configurations, and the
notices were scored with our own `experiments.Truth` and `experiments.score()`, with no changes to either.
Every number below was printed by `baselines/zeek/eval_zeek.py`. The raw output is in `eval_friday.txt`,
`eval_friday_asshipped.txt` and `eval_wednesday.txt`, and the full scores are in `friday_scores.json`,
`friday_asshipped_scores.json` and `wednesday_scores.json`, all in this folder.

## 1. What was run

| Item | Value |
|---|---|
| Zeek | 9.0.0 (Homebrew bottle `zeek--9.0.0_1.arm64_tahoe`, installed 2026-10-22) |
| Scan script | `policy/misc/scan.zeek` is **not** in Zeek 9.0.0 (`$(zeek-config --script_dir)/policy/misc/` has no scan.zeek). It was deprecated in 6.0 and removed in 6.1. We used the copy from **zeek/zeek tag `v6.0.9`**, the last release that shipped it (tag object `6613675300a5ed3f3e8a9b2669f1b0fac1c4b253`, commit `7a7864f89297e0fc3f3779ec2f8dc5100d8449c0`), downloaded from `https://raw.githubusercontent.com/zeek/zeek/v6.0.9/scripts/policy/misc/scan.zeek` and stored as `baselines/zeek/scan_v6.0.9_original.zeek` (sha256 `8a23528522ad5cb70cc510ab9778052a24463f53cb72ef94a15e308e0679cc0d`) |
| Changes to scan.zeek | **None.** It loads on 9.0.0 unchanged. Its `@deprecated` line only prints a warning (see `out_*/stderr.log`) |
| Compatibility shim | `baselines/zeek/sumstats_epoch_compat.zeek`, explained in section 2. It changes no threshold, interval or detection logic |
| Site | `baselines/zeek/site.zeek`: `redef Site::local_nets += { 192.168.10.0/24 };`, so 172.16.0.1 counts as remote |
| Suppressed-notice logger | `baselines/zeek/log_suppressed.zeek` only observes. It writes `scan_suppressed.log` from the `Notice::suppressed` event, because Zeek does not log suppressed notices itself |
| Checksums | `zeek -C` (the capture has bad checksums) |
| Run time | about 2.5 min per Friday run (`real 145.43` s), with the two runs in parallel on an Apple-silicon Mac. Wednesday took 167 s |

Scan.zeek defaults (v6.0.9) and the two configurations. Both were fixed before any result was seen:

| Parameter | (a) DEFAULT | (b) MATCHED |
|---|---|---|
| `Scan::port_scan_threshold` (distinct failed ports to one victim; fires when the count is **>=** threshold) | 15.0 (default) | **10.0** |
| `Scan::port_scan_interval` (SumStats epoch, fixed and not sliding) | 5 min (default) | **60 s** |
| `Scan::addr_scan_threshold` (distinct hosts on one port) | 25.0 (default) | 25.0 (default) |
| `Scan::addr_scan_interval` | 5 min (default) | 5 min (default) |
| `Notice::default_suppression_interval` (identifier = scanner address) | 1 h (Zeek 9 default) | 1 h (Zeek 9 default) |

Mapping for MATCHED: our rejected_probes rule fires on **more than 10 failed probes** (RST answering a SYN,
or ICMP unreachable) per source in a **sliding** 60 s window. Scan.zeek counts **distinct ports** that one
scanner failed to connect to on one victim. It fires at **>= 10** inside a **fixed** 60 s epoch, and the
count resets at each epoch boundary. This is as close as the script's structure allows. The
differences are listed here and were not tuned away.

The script's "failed connection" is a Zeek connection that was rejected (REJ), was a connection attempt
that never got an answer, or was reset before any data was sent (`is_failed_conn` in the script). It
covers TCP only.

Not used: the zkg package `ncsa/bro-simple-scan` (master `35cf19cf64ba9f9989022a56dce0c8ad6ae2f3f2`), which
the deprecation message recommends. It has no separate port-scan threshold and no epoch. Instead it has one
`scan_threshold = 25` over distinct host+port pairs, a `scan_timeout = 15min` read-expire, and darknet
logic that needs the extra package `ncsa/bro-is-darknet`. MATCHED (10 ports / 60 s) therefore cannot be
mapped onto it one-to-one, while scan.zeek maps exactly. Running it would be a third, different baseline.

## 2. Deviation: Zeek >= 7.1 silently disables scan.zeek's epochs (found, fixed with a shim, disclosed)

The first run used Zeek 9.0.0 exactly as shipped (outputs `<data>/zeek/out_default_asshipped/` and
`<data>/zeek/out_matched_asshipped/`). DEFAULT and MATCHED produced the **same five notices**, and their
messages showed evidence windows far longer than the epoch: "172.16.0.1 scanned at least 15 unique ports
... in 56m13s" and "192.168.10.9 scanned at least 25 unique hosts on port 443/tcp in 308m20s".

Cause, found in the source: since Zeek 7.1, `base/frameworks/sumstats/non-cluster.zeek::do_finish_epoch()`
starts with `if ( ss$name !in result_store || ! ss?$epoch_result ) return;`. A SumStat without an
`$epoch_result` callback, which describes both of scan.zeek's SumStats, is therefore never reset and never
gets its next epoch scheduled. The 5 min or 60 s epoch silently becomes a single epoch for the whole
capture. In v6.0.9, the release scan.zeek comes from, `finish_epoch()` reset such a SumStat and
rescheduled it. We checked the upstream sources: v6.0.9, v7.0.0 and v7.0.5 reschedule, while v7.1.0,
v7.2.0, v8.0.0 and the installed 9.0.0 do not.

Fix: `sumstats_epoch_compat.zeek` adds a low-priority `SumStats::finish_epoch` handler that does what
v6.0.9 did, for SumStats without `$epoch_result` only: reset, then schedule the next epoch. We tested it
on `tests/data/large_evaluation_dataset.pcap` with a 5 s epoch and a debug print. Without the shim, the
port-scan epoch ended once, at the first packet. With the shim, it ended every 5 s. With the shim, the
Friday notices report evidence spans of "0m0s" instead of 56 min.

Disclosure: the shim was written **after** the as-shipped results had been seen, because those results
showed that the configured intervals were being ignored. It changes no threshold or interval. It makes
Zeek apply the intervals that both pre-registered configurations specify. The shimmed runs are the
primary result, and the as-shipped runs are kept as a diagnostic (section 4).

## 3. Results, Friday (primary: scan.zeek v6.0.9 + epoch shim on Zeek 9.0.0)

Scoring is `experiments.score(Truth(DAYS['friday'], '<data>/friday.cache'), dets, min_score=1)`. The unit is
one second. DEV = PortScan segment (6.67 h) and TEST = DDoS segment (1.38 h). Positives are PortScan 594 s
and DDoS 1095 s. Every Scan::* notice becomes a detection `(ts, notice src, 1, ['zeek_scan'])`:

- **strict**: a notice covers only its own second.
- **epoch**: a notice also covers the preceding `interval` seconds for the same source (300 s, or 60 s for
  Port_Scan in MATCHED). **This is generous to Zeek**, because it back-dates detections the notice could not
  have raised before its timestamp. The two conversions are never mixed.

TTD = time to the first true alert, in seconds from the window start (PortScan 13:55:00 ADT). It always
uses the real notice time (the strict value). Under the epoch conversion, `score()`'s own ttd is back-dated
(3105 s DEFAULT, 3345 s MATCHED; see the JSON) and is not used.

| Config | Conversion | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | PortScan recall | DDoS recall | TTD PortScan (s) | TTD DDoS (s) | notices attacker / others |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| (a) default | strict | 100.0 | 0.2 | 0.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2 | 0.0 | 3405 | - | 1 / 0 |
| (a) default | epoch | 100.0 | 1.7 | 3.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.7 | 0.0 | 3405 | - | 1 / 0 |
| (b) matched | strict | 100.0 | 0.2 | 0.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2 | 0.0 | 3405 | - | 1 / 0 |
| (b) matched | epoch | 100.0 | 1.7 | 3.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.7 | 0.0 | 3405 | - | 1 / 0 |

Notices: each configuration logged exactly one notice, `Scan::Port_Scan` 172.16.0.1 -> 192.168.10.50 at
14:51:45 ADT (ts 1499449905.454). There were no Address_Scan notices and no notices from any other host.
Scan.zeek has no flood or DoS detector, so the TEST (DDoS) segment gets nothing, as expected.

Suppression (default 1 h, identifier = scanner address): **DEFAULT suppressed 4** repeat Port_Scan notices
for 172.16.0.1, at 14:54:48, 15:08:01, 15:09:52 and 15:22:02. **MATCHED suppressed 10**, at 14:52:41,
14:54:15, 14:54:42, 14:55:41, 15:08:01, 15:08:43, 15:09:52, 15:22:02, 15:22:43 and 15:23:43, all ADT.
None was suppressed for any other source. This comes from `scan_suppressed.log`.

Post-hoc, **informational only, not a configuration**: if the suppressed notices had been logged as well,
PortScan recall would be 0.8 % strict / 23.6 % epoch for DEFAULT, and 1.7 % strict / 32.5 % epoch for
MATCHED, with 0 false-alarm seconds (`posthoc_with_suppressed` in `friday_scores.json`).

### Our rules on the same data, for comparison

These rows were copied by `eval_zeek.py` from `results/friday/results.md`. The `ttd` values come from
`results/friday/results.json` (`by_score["1"].windows`):

| Source | Configuration | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | PortScan recall | DDoS recall | TTD PortScan (s) | TTD DDoS (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| results.md:13 | count / fixed | 99.3 | 23.7 | 38.3 | 0.1 | 98.7 | 78.1 | 87.2 | 8.0 | 23.7 | 78.1 | 3405 | 44 |
| results.md:15 | behaviour / fixed | 100.0 | 84.7 | 91.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 84.7 | 0.0 | 51 | - |
| results.md:41 | only port_sweep | 100.0 | 23.7 | 38.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 23.7 | 0.0 | 3405 | - |
| results.md:46 | only rejected_probes | 100.0 | 84.7 | 91.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 84.7 | 0.0 | 52 | - |

### Why Zeek fires 56 minutes in

From `attacker_conn_timeline.txt`, built from Zeek's own conn.log by `baselines/zeek/conn_timeline.py`: from
13:55 to 14:19 ADT the attacker's failed connections to 192.168.10.50 hit only **5 distinct TCP ports**, or
7 (port, proto) pairs if UDP is counted. Scan.zeek counts TCP only. That is a few hundred REJ/RSTO
connections in short bursts. The 1000-port sweep starts at 14:51, with 10,855 REJ in that minute. No
distinct-port detector with a threshold of 10, 15 or 20 ports can fire before then. This explains why
Zeek's TTD (3405 s) equals the TTD of our own distinct-port rule `port_sweep` (> 20 distinct ports per
1 s) and of `count / fixed`. Our `rejected_probes` counts failed probes rather than distinct ports, so it
already fires on the early bursts (TTD 52 s).

## 4. Diagnostic: Zeek 9.0.0 as shipped (no epoch shim)

These runs do not realise the configured intervals (section 2). They are not a baseline row.

| Config | Conversion | DEV P | DEV R | DEV F1 | DEV FP/h | TEST P | TEST R | TEST F1 | TEST FP/h | PortScan recall | DDoS recall | TTD PortScan (s) | TTD DDoS (s) | notices attacker / others |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| default_asshipped | strict | 33.3 | 0.2 | 0.3 | 0.3 | 0.0 | 0.0 | 0.0 | 1.5 | 0.2 | 0.0 | 3405 | - | 1 / 4 |
| default_asshipped | epoch | 1.2 | 1.7 | 1.4 | 119.2 | 0.0 | 0.0 | 0.0 | 174.9 | 1.7 | 0.0 | 3405 | - | 1 / 4 |
| matched_asshipped | strict | 33.3 | 0.2 | 0.3 | 0.3 | 0.0 | 0.0 | 0.0 | 1.5 | 0.2 | 0.0 | 3405 | - | 1 / 4 |
| matched_asshipped | epoch | 1.2 | 1.7 | 1.4 | 119.2 | 0.0 | 0.0 | 0.0 | 174.9 | 1.7 | 0.0 | 3405 | - | 1 / 4 |

The 4 "other" notices are `Scan::Address_Scan` from 192.168.10.9, .12, .5 and .25 (port 443/tcp). They
built up over 308 to 383 minutes because the epoch never reset. With the epoch shim they disappear.

## 5. Wednesday false-alarm check (config (a) DEFAULT + shim, nothing tuned)

`Truth(DAYS['wednesday'], '<data>/wednesday.cache')`, with one segment of 8.46 h. Zeek wrote **no notice.log**
(0 Scan notices), so there are **0 false-alarm seconds, 0.00 per hour**, under both conversions. It also
detects none of the four DoS windows; scan.zeek is not a DoS detector. Zeek's conn.log for this run covered
ts 1499254967 to 1499284833, so the whole capture was processed.

## 6. Plain facts

- **Zeek does not beat our behaviour rules on the PortScan.** On DEV, Zeek's F1 is 0.3 (strict) or 3.3
  (epoch-credited, generous) under both configurations. `behaviour / fixed` and `only rejected_probes`
  reach F1 91.7. PortScan recall is 0.2 % or 1.7 % for Zeek, against 84.7 %. Zeek's first true alert comes
  3405 s after the window starts, against 51 to 52 s.
- Zeek's precision is 100 % and it raised no false alarm on Friday (with the shim) or on Wednesday. Our
  behaviour rules are also at 100 % precision and 0.0 FP/h on DEV.
- On this data, Zeek scan.zeek ties our **distinct-port** rules on time to detection (3405 s for
  `port_sweep` and `count / fixed`). It is far below them on per-second recall (23.7 %), mainly because it
  emits one summary notice per epoch and then suppresses the scanner for 1 h. The MATCHED thresholds
  (10 ports / 60 s) did not change Zeek's logged result at all compared with DEFAULT. They only changed
  how many notices were suppressed (10 instead of 4).
- Even post-hoc, with suppression removed and full epoch credit, Zeek reaches 32.5 % PortScan recall
  (MATCHED), still below the 84.7 % of `rejected_probes`.
- Caveat for the paper: a per-second coverage metric favours detectors that alert continuously, and
  scan.zeek is designed to raise one notice per scanner. At the level of the question "was the scanner
  identified?", Zeek identifies 172.16.0.1 correctly, but only at 14:51:45 ADT, 56 min into the window.

## 7. Reproduce

```bash
brew install zeek                      # 9.0.0
baselines/zeek/run_zeek.sh default matched          # primary runs, with epoch shim -> <data>/zeek/out_default/, out_matched/
baselines/zeek/run_zeek.sh default_asshipped matched_asshipped   # diagnostic, Zeek 9 as shipped
baselines/zeek/run_zeek.sh wednesday_default        # false-alarm check
python -m baselines.zeek.eval_zeek friday default=zeek/out_default matched=zeek/out_matched
python -m baselines.zeek.eval_zeek friday --tag asshipped default_asshipped=zeek/out_default_asshipped matched_asshipped=zeek/out_matched_asshipped
python -m baselines.zeek.eval_zeek wednesday wednesday_default=zeek/out_wednesday_default
python baselines/zeek/conn_timeline.py data/zeek/out_default/conn.log > results/zeek_baseline/attacker_conn_timeline.txt
```

Each run executes `zeek -C -r <pcap> scan_v6.0.9_original.zeek site.zeek log_suppressed.zeek
[sumstats_epoch_compat.zeek] config_<default|matched>.zeek` inside `<data>/zeek/out_<name>/`.

Kept outputs: `notice.log`, `scan_suppressed.log` (when Zeek wrote one), and `stdout.log`/`stderr.log` with
`/usr/bin/time` output. The protocol logs (dns, http, ssl and so on) are deleted by `run_zeek.sh`.
**conn.log** came to 69.6 MB for each Friday run and 66.7 MB for Wednesday, so all were under 100 MB. They
were deleted after `attacker_conn_timeline.txt` had been extracted, to keep large files out of git. The
timeline was identical from the DEFAULT and MATCHED conn.logs. For the as-shipped runs, the protocol logs
and conn.log were deleted by hand after the same check.

Tests after the work: `python -m pytest -q` gave 37 passed (53 in the current repository).
