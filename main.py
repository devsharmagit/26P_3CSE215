"""
Rule-Based Network Intrusion & Packet Analyzer - command line.

    python main.py rules                                  # show the rules in config/rules.yaml, in plain words
    python main.py detect -f capture.pcap                 # run the rules over a capture, print scored detections
    python main.py analyze -f capture.pcap                # traffic report + detections -> report/<name>/report.html
    python main.py analyze -f friday.cache --truth friday # ... with the dataset's attack windows shaded
    sudo python main.py live -i en0                       # live capture (needs scapy and root)

Common options: -r/--rules <file> (default config/rules.yaml), --policy fixed|adaptive (override every rule).
Captures can be pcap, pcapng or a cache built by `python -m nids.pcapng_reader in.pcap out.cache`.
The old form `python main.py -f capture.pcap` still works and means `detect`.
"""
import argparse
import datetime
import json
import os
import sys
import time

from nids import pcapng_reader as pr
from nids.paths import ROOT, RULES
from nids.rule_set import RuleFileError, describe, load_rules


def _rules(args):
    try:
        rs = load_rules(args.rules)
    except (RuleFileError, OSError) as e:
        sys.exit(f'rule file error: {e}')
    if getattr(args, 'policy', None):
        rs = rs.variant(policy=args.policy)
    return rs


def _tz(args):
    from nids.days import ADT, DAYS
    if getattr(args, 'truth', None):
        return ADT if not DAYS[args.truth].relative else None
    if getattr(args, 'utc_offset', None) is not None:
        return datetime.timezone(datetime.timedelta(hours=args.utc_offset))
    return None


def cmd_rules(args):
    print(describe(_rules(args)))


def cmd_detect(args):
    from nids.alerts import log_detection
    from nids.engine import RuleEngine
    rs = _rules(args)
    tz = _tz(args)
    out = open(args.output, 'w') if args.output else None
    shown = [0]

    def on_det(d):
        if d.score >= args.min_score:
            if shown[0] < args.max_print or args.max_print < 0:
                log_detection(d, tz)
            shown[0] += 1
            if out:
                out.write(json.dumps(d.to_dict()) + '\n')

    eng = RuleEngine(rs, on_detection=on_det)
    t0 = time.time()
    for rec in pr.iter_any(args.file):
        if rec[3] in (1, 6, 17):
            eng.process_packet(pr.to_features(rec))
    eng.flush()
    dt = time.time() - t0
    if 0 <= args.max_print < shown[0]:
        print(f'... {shown[0] - args.max_print:,} more detections not printed (use --max-print -1 or -o file.jsonl)')
    print(f'{eng.packets:,} packets in {dt:.1f} s ({eng.packets / max(dt, 1e-9):,.0f} pkt/s); '
          f'{shown[0]:,} detections with score >= {args.min_score:g}' + (f'; written to {args.output}' if out else ''))
    if out:
        out.close()


def cmd_analyze(args):
    from nids import analyzer
    from nids.days import DAYS
    rs = None if args.no_rules else _rules(args)
    truth = None
    if args.truth:
        day = DAYS[args.truth]
        if day.relative:
            sys.exit('--truth works for real capture days (friday, wednesday)')
        truth = {'day': day.name, 'windows': [{'name': w.name, 'start': w.start, 'end': w.end} for w in day.windows if w.in_scope]}
    tz = _tz(args)
    name = os.path.splitext(os.path.basename(args.file))[0]
    out_dir = args.output or os.path.join(ROOT, 'report', name)
    print(f'analysing {args.file} ...', flush=True)
    res = analyzer.analyze(args.file, rs, truth=truth, tz=tz, top=args.top)
    analyzer.print_summary(res)
    path = analyzer.write_report(res, out_dir)
    print(f'\nreport: {path}')


def cmd_live(args):
    from scapy.all import sniff
    from nids.alerts import log_detection
    from nids.engine import RuleEngine
    from nids.packet_parser import parse_packet
    eng = RuleEngine(_rules(args), on_detection=lambda d: d.score >= args.min_score and log_detection(d, None))

    def cb(packet):
        f = parse_packet(packet)
        if f and f['protocol'] in (1, 6, 17):
            eng.process_packet(f)
    print(f'live capture on {args.interface or "default interface"} (Ctrl-C to stop)...')
    try:
        sniff(iface=args.interface, prn=cb, store=False, count=args.count)
    except KeyboardInterrupt:
        pass
    eng.flush()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0].startswith('-') and argv[0] not in ('-h', '--help'):
        argv = ['detect'] + argv  # legacy: python main.py -f file.pcap
    p = argparse.ArgumentParser(description='Rule-Based Network Intrusion & Packet Analyzer')
    sub = p.add_subparsers(dest='cmd', required=True)

    def common(sp):
        sp.add_argument('-r', '--rules', default=RULES, help='rule file (default config/rules.yaml)')
        sp.add_argument('--policy', choices=('fixed', 'adaptive'), help='force this threshold policy on every rule')
        sp.add_argument('--min-score', type=float, default=1, help='only report detections with at least this score')

    sp = sub.add_parser('rules', help='list the rules in plain words')
    sp.add_argument('-r', '--rules', default=RULES)
    sp.set_defaults(func=cmd_rules)

    sp = sub.add_parser('detect', help='run the rules over a capture file')
    sp.add_argument('-f', '--file', required=True, help='pcap / pcapng / cache')
    sp.add_argument('-o', '--output', help='also write every detection as JSON lines to this file')
    sp.add_argument('--max-print', type=int, default=50, help='print at most this many detections (-1 = all)')
    sp.add_argument('--utc-offset', type=float, help='show times in this UTC offset (hours); default local time')
    sp.add_argument('--truth', choices=('friday', 'wednesday'), help='CICIDS2017 day (times shown in ADT)')
    common(sp)
    sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser('analyze', help='traffic report (protocols, talkers, services, timeline) + detections')
    sp.add_argument('-f', '--file', required=True, help='pcap / pcapng / cache')
    sp.add_argument('-o', '--output', help='report directory (default report/<capture name>/)')
    sp.add_argument('--no-rules', action='store_true', help='traffic statistics only')
    sp.add_argument('--truth', choices=('friday', 'wednesday'), help='shade this CICIDS2017 day\'s attack windows')
    sp.add_argument('--utc-offset', type=float, help='show times in this UTC offset (hours); default local time')
    sp.add_argument('--top', type=int, default=10, help='rows in the top-N tables')
    common(sp)
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser('live', help='live capture with scapy (root needed)')
    sp.add_argument('-i', '--interface', help='interface, e.g. en0 / eth0')
    sp.add_argument('-c', '--count', type=int, default=0, help='stop after this many packets (0 = never)')
    common(sp)
    sp.set_defaults(func=cmd_live)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    main()
