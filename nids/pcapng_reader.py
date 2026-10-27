"""
Fast streaming reader for large pcapng captures (e.g. raw CICIDS2017 PCAPs).

scapy.sniff(offline=...) is far too slow for multi-GB captures, so this parses the
pcapng block structure and the Ethernet/IPv4/TCP/UDP/ICMP headers directly with struct.

Two layers:
  * iter_frames(path)       -> yields (ts, src, dst, proto, sport, dport, flags, length) for pcapng OR classic pcap
                               (for ICMP, sport/dport carry the ICMP type/code; length = IP total length)
  * iter_packets(path)      -> legacy 7-tuples (ts, src, dst, proto, sport, dport, flags), pcapng only
  * build_cache(path, out)  -> one pass over the capture, writes a compact fixed-width binary cache (v2)
  * iter_records(path)      -> 8-tuples from a cache (v1 caches report length 0)
  * iter_cache(path)        -> legacy 7-tuples from a cache (v1 or v2)
  * iter_any(path)          -> 8-tuples from a cache, a pcapng or a classic pcap (picked by content)
  * to_features(record)     -> dict in exactly the format packet_parser.parse_packet() produces
"""
import socket
import struct
import sys
import time

REC = struct.Struct('<dIIBHHB')     # v1 cache: ts, src, dst, proto, sport, dport, flags(raw byte)
REC2 = struct.Struct('<dIIBHHBH')   # v2 cache: ... + IP total length
CACHE_MAGIC = b'NIDSCv2\0'           # v2 caches start with this; v1 caches have no header
_FLAG_CHARS = (('F', 0x01), ('S', 0x02), ('R', 0x04), ('P', 0x08), ('A', 0x10), ('U', 0x20), ('E', 0x40), ('C', 0x80))
_flag_cache = {}


def flags_to_str(b):
    """Raw TCP flag byte -> scapy-style string (e.g. 0x12 -> 'SA')."""
    s = _flag_cache.get(b)
    if s is None:
        # scapy orders flags as FSRPAUEC
        s = ''.join(c for c, bit in _FLAG_CHARS if b & bit)
        _flag_cache[b] = s
    return s


def ip_to_str(n):
    return socket.inet_ntoa(struct.pack('>I', n))


def _iter_pcapng(path, chunk_size=64 * 1024 * 1024):
    """Yield (ts, src_int, dst_int, proto, sport, dport, flags_byte, ip_len) for every IPv4 packet."""
    buf = b''
    pos = 0
    linktype = 1
    tsdiv = 1e6
    unpack_from = struct.unpack_from
    with open(path, 'rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            buf = buf[pos:] + data
            pos = 0
            n = len(buf)
            while n - pos >= 12:
                btype, blen = unpack_from('<II', buf, pos)
                if blen < 12 or blen > 0x10000000:
                    raise ValueError(f'corrupt pcapng block at offset {pos}')
                if n - pos < blen:
                    break  # need more data
                if btype == 6:  # Enhanced Packet Block
                    ts_hi, ts_lo, caplen, _origlen = unpack_from('<IIII', buf, pos + 12)
                    ts = ((ts_hi << 32) | ts_lo) / tsdiv
                    p = pos + 28
                    l3 = _frame_l3(buf, p, caplen, linktype, unpack_from)
                    if l3 is not None:
                        yield (ts,) + _l3(buf, p, l3, caplen, unpack_from)
                elif btype == 1:  # Interface Description Block
                    linktype = unpack_from('<H', buf, pos + 8)[0]
                    # tsresol option (code 9); default is microseconds
                    o = pos + 16
                    end = pos + blen - 4
                    while o + 4 <= end:
                        code, olen = unpack_from('<HH', buf, o)
                        if code == 0:
                            break
                        if code == 9:
                            res = buf[o + 4]
                            tsdiv = float(2 ** (res & 0x7F)) if res & 0x80 else float(10 ** res)
                        o += 4 + ((olen + 3) & ~3)
                pos += blen
            # loop continues; leftover bytes carried via buf[pos:]
    # trailing partial block is ignored


def _l3(buf, p, l3, caplen, unpack_from):
    """Parse the IPv4 header at buf[l3]; p = frame start. Returns (src, dst, proto, sport, dport, flags, ip_len)."""
    vihl = buf[l3]
    ihl = (vihl & 0x0F) * 4
    ip_len = unpack_from('>H', buf, l3 + 2)[0]
    proto = buf[l3 + 9]
    src, dst = unpack_from('>II', buf, l3 + 12)
    l4 = l3 + ihl
    sport = dport = 0
    flags = 0
    if proto == 6 and caplen >= (l4 - p) + 14:
        sport, dport = unpack_from('>HH', buf, l4)
        flags = buf[l4 + 13]
    elif proto == 17 and caplen >= (l4 - p) + 4:
        sport, dport = unpack_from('>HH', buf, l4)
    elif proto == 1 and caplen >= (l4 - p) + 2:
        sport, dport = buf[l4], buf[l4 + 1]  # ICMP type, code
    return src, dst, proto, sport, dport, flags, ip_len


def _frame_l3(buf, p, caplen, linktype, unpack_from):
    """Offset of the IPv4 header inside a frame starting at p, or None if the frame is not IPv4."""
    if linktype == 1:  # Ethernet
        if caplen < 14:
            return None
        ethertype = unpack_from('>H', buf, p + 12)[0]
        l3 = p + 14
        if ethertype == 0x8100 and caplen >= 18:  # 802.1Q VLAN
            ethertype = unpack_from('>H', buf, p + 16)[0]
            l3 = p + 18
        if ethertype != 0x0800:
            return None
    elif linktype in (101, 228):  # raw IPv4
        l3 = p
    elif linktype == 0:  # BSD loopback (4-byte family)
        l3 = p + 4
    else:
        return None
    if caplen < (l3 - p) + 20 or (buf[l3] >> 4) != 4:
        return None
    return l3


def _iter_pcap(path, chunk_size=64 * 1024 * 1024):
    """Classic libpcap file (as written by scapy/tcpdump). Same tuples as _iter_pcapng."""
    unpack_from = struct.unpack_from
    with open(path, 'rb') as f:
        hdr = f.read(24)
        magic = hdr[:4]
        if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
            e = '<'
        elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
            e = '>'
        else:
            raise ValueError('not a pcap file')
        tsdiv = 1e9 if magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1e6
        linktype = struct.unpack(e + 'I', hdr[20:24])[0] & 0x0FFFFFFF
        rec_fmt = e + 'IIII'
        buf = b''
        pos = 0
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            buf = buf[pos:] + data
            pos = 0
            n = len(buf)
            while n - pos >= 16:
                ts_s, ts_frac, caplen, _orig = unpack_from(rec_fmt, buf, pos)
                if n - pos < 16 + caplen:
                    break
                p = pos + 16
                l3 = _frame_l3(buf, p, caplen, linktype, unpack_from)
                if l3 is not None:
                    yield (ts_s + ts_frac / tsdiv,) + _l3(buf, p, l3, caplen, unpack_from)
                pos += 16 + caplen


def iter_frames(path):
    """(ts, src, dst, proto, sport, dport, flags, ip_len) for every IPv4 packet of a pcapng or classic pcap."""
    with open(path, 'rb') as f:
        magic = f.read(4)
    if magic == b'\x0a\x0d\x0d\x0a':
        return _iter_pcapng(path)
    return _iter_pcap(path)


def iter_packets(path, chunk_size=64 * 1024 * 1024):
    """Legacy API: (ts, src_int, dst_int, proto, sport, dport, flags_byte) for every IPv4 packet of a pcapng."""
    for ts, src, dst, proto, sport, dport, flags, _len in _iter_pcapng(path, chunk_size):
        if proto not in (6, 17):
            sport = dport = 0
        yield ts, src, dst, proto, sport, dport, flags


def build_cache(path, out_path, progress_every=2_000_000):
    """Single pass over a pcapng/pcap; writes a v2 cache (header + fixed-width records). Returns packet count."""
    t0 = time.time()
    count = 0
    pack = REC2.pack
    with open(out_path, 'wb') as out:
        out.write(CACHE_MAGIC)
        batch = []
        for rec in iter_frames(path):
            batch.append(pack(*rec))
            count += 1
            if len(batch) >= 100_000:
                out.write(b''.join(batch))
                batch = []
            if count % progress_every == 0:
                print(f'  {count:,} packets ({time.time() - t0:.0f}s)', file=sys.stderr, flush=True)
        out.write(b''.join(batch))
    return count


def _cache_format(path):
    with open(path, 'rb') as f:
        return 2 if f.read(len(CACHE_MAGIC)) == CACHE_MAGIC else 1


def iter_records(path, chunk_records=200_000):
    """8-tuples (ts, src, dst, proto, sport, dport, flags, ip_len) from a v1 or v2 cache."""
    if _cache_format(path) == 1:
        for r in iter_cache(path, chunk_records):
            yield r + (0,)
        return
    with open(path, 'rb') as f:
        f.seek(len(CACHE_MAGIC))
        while True:
            data = f.read(REC2.size * chunk_records)
            if not data:
                break
            yield from REC2.iter_unpack(data)


def iter_cache(path, chunk_records=200_000):
    """Legacy API: 7-tuples (no length) from a v1 or v2 cache."""
    if _cache_format(path) == 2:
        for r in iter_records(path, chunk_records):
            yield r[:7]
        return
    size = REC.size
    with open(path, 'rb') as f:
        while True:
            data = f.read(size * chunk_records)
            if not data:
                break
            yield from REC.iter_unpack(data)


def iter_any(path):
    """8-tuples from whatever `path` is: a cache built by build_cache, a pcapng or a classic pcap."""
    with open(path, 'rb') as f:
        head = f.read(8)
    if head == CACHE_MAGIC:
        return iter_records(path)
    if head[:4] in (b'\x0a\x0d\x0d\x0a', b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        return iter_frames(path)
    return iter_records(path)  # v1 cache (no header)


def to_features(rec):
    """Convert a cache record (7- or 8-tuple) to the dict format of packet_parser.parse_packet()."""
    ts, src, dst, proto, sport, dport, flags = rec[:7]
    length = rec[7] if len(rec) > 7 else 0
    if proto == 6:
        return {'timestamp': ts, 'src_ip': ip_to_str(src), 'dst_ip': ip_to_str(dst), 'protocol': 6,
                'src_port': sport, 'dst_port': dport, 'tcp_flags': flags_to_str(flags), 'length': length}
    if proto == 17:
        return {'timestamp': ts, 'src_ip': ip_to_str(src), 'dst_ip': ip_to_str(dst), 'protocol': 17,
                'src_port': sport, 'dst_port': dport, 'tcp_flags': None, 'length': length}
    feats = {'timestamp': ts, 'src_ip': ip_to_str(src), 'dst_ip': ip_to_str(dst), 'protocol': proto,
             'src_port': None, 'dst_port': None, 'tcp_flags': None, 'length': length}
    if proto == 1 and len(rec) > 7:
        feats['icmp_type'], feats['icmp_code'] = sport, dport
    return feats


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('usage: python -m nids.pcapng_reader <in.pcap(ng)> <out.cache>')
    n = build_cache(sys.argv[1], sys.argv[2])
    print(f'wrote {n:,} packets to {sys.argv[2]}')
