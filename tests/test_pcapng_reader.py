"""Tests for pcapng_reader: build a tiny pcapng by hand and check parsing, flags and the cache round-trip."""
import socket
import struct

from nids import pcapng_reader as pr


def block(btype, body):
    total = 12 + len(body)
    pad = (-len(body)) % 4
    total += pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)


def eth_ip(proto, src, dst, l4):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return b'\x00' * 12 + b'\x08\x00' + ip + l4


def tcp(sport, dport, flags):
    return struct.pack('>HHIIBBHHH', sport, dport, 0, 0, 5 << 4, flags, 1000, 0, 0)


def epb(ts_us, frame):
    body = struct.pack('<IIIII', 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(frame), len(frame)) + frame
    return block(6, body)


def make_pcapng(path):
    shb = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack('<HHI', 1, 0, 0x40000))  # Ethernet, no options -> microseconds
    frames = [
        epb(1_000_000, eth_ip(6, '10.0.0.1', '10.0.0.2', tcp(40000, 80, 0x02))),                      # SYN
        epb(1_500_000, eth_ip(6, '10.0.0.2', '10.0.0.1', tcp(80, 40000, 0x12))),                      # SYN-ACK
        epb(2_000_000, eth_ip(17, '10.0.0.1', '10.0.0.3', struct.pack('>HHHH', 5000, 53, 8, 0))),    # UDP
        epb(3_000_000, eth_ip(1, '10.0.0.1', '10.0.0.4', b'\x08\x00\x00\x00\x00\x00\x00\x00')),      # ICMP
        epb(4_000_000, b'\x00' * 12 + b'\x86\xdd' + b'\x00' * 40),                                    # IPv6: skipped
    ]
    with open(path, 'wb') as f:
        f.write(shb + idb + b''.join(frames))


def test_iter_packets(tmp_path):
    p = tmp_path / 't.pcapng'
    make_pcapng(p)
    recs = list(pr.iter_packets(str(p)))
    assert len(recs) == 4  # IPv6 frame ignored
    ts, src, dst, proto, sport, dport, flags = recs[0]
    assert ts == 1.0 and pr.ip_to_str(src) == '10.0.0.1' and pr.ip_to_str(dst) == '10.0.0.2'
    assert (proto, sport, dport, flags) == (6, 40000, 80, 0x02)
    assert recs[1][6] == 0x12
    assert recs[2][3:6] == (17, 5000, 53)
    assert recs[3][3] == 1 and recs[3][4:6] == (0, 0)


def test_chunk_boundaries(tmp_path):
    """Blocks split across read chunks must still parse (tiny chunk size forces splits)."""
    p = tmp_path / 't.pcapng'
    make_pcapng(p)
    assert list(pr.iter_packets(str(p), chunk_size=37)) == list(pr.iter_packets(str(p)))


def test_flags_to_str_matches_scapy_order():
    assert pr.flags_to_str(0x02) == 'S'
    assert pr.flags_to_str(0x12) == 'SA'
    assert pr.flags_to_str(0x18) == 'PA'
    assert pr.flags_to_str(0x11) == 'FA'
    assert pr.flags_to_str(0x14) == 'RA'


def test_cache_roundtrip_and_features(tmp_path):
    p = tmp_path / 't.pcapng'
    c = tmp_path / 't.cache'
    make_pcapng(p)
    assert pr.build_cache(str(p), str(c)) == 4
    feats = [pr.to_features(r) for r in pr.iter_cache(str(c))]
    assert feats[0] == {'timestamp': 1.0, 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'protocol': 6,
                        'src_port': 40000, 'dst_port': 80, 'tcp_flags': 'S', 'length': 0}
    assert feats[2]['protocol'] == 17 and feats[2]['tcp_flags'] is None
    assert feats[3]['protocol'] == 1 and feats[3]['dst_port'] is None
