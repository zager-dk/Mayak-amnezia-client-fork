#!/usr/bin/env python3
"""Mayak: builds the embedded list of Russian IPv4 networks for «Россия напрямую».

Source: RIPE NCC delegated statistics (public), file delegated-ripencc-extended-latest,
records with country RU and type ipv4 (allocated/assigned).

Steps:
1. merge all RU ranges into disjoint intervals;
2. coarsen with a tolerance: a CIDR block is taken whole when at least --min-share of it is
   Russian (the rest of it goes direct too); otherwise it is split further;
3. pieces smaller than --min-prefix are dropped (they stay in the VPN — the safe direction);
4. adjacent blocks are merged again.

Output: one CIDR per line, '#' header with source date and parameters. Lines starting with '!'
are priority networks: the RIPE RU records containing the addresses of --priority-domains
(resolved at build time; the resolved addresses are written to --priority-snapshot so the list
can be rebuilt without DNS via --priority-from-snapshot). The client never drops them when it
coarsens the list to a route budget.

Usage:
  python -I gen_ru_networks.py INPUT --out FILE [--min-share 0.9] [--min-prefix 24]
  python -I gen_ru_networks.py INPUT --stats
"""
import argparse
import hashlib
import ipaddress
import sys


def load_ru_intervals(path, records=None):
    intervals, date = [], ''
    with open(path, encoding='ascii', errors='strict') as f:
        for line in f:
            if line.startswith('#'):
                continue
            parts = line.rstrip('\n').split('|')
            if len(parts) >= 7 and parts[0] == '2' and not date:
                date = parts[5]
            if len(parts) < 7 or parts[1] != 'RU' or parts[2] != 'ipv4':
                continue
            if parts[6] not in ('allocated', 'assigned'):
                continue
            start = int(ipaddress.IPv4Address(parts[3]))
            count = int(parts[4])
            if count <= 0 or start + count > 2 ** 32:
                raise ValueError('bad record: ' + line.strip())
            intervals.append((start, start + count))
            if records is not None:
                records.append((start, start + count))
    return merge(intervals), date


def resolve_ipv4(names):
    import socket
    out = {}
    for name in names:
        try:
            infos = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
            out[name] = sorted({i[4][0] for i in infos})
        except OSError:
            out[name] = []
    return out


def priority_records(records, addresses):
    keep = set()
    for ip in addresses:
        v = int(ipaddress.IPv4Address(ip))
        for s, e in records:
            if s <= v < e:
                keep.add((s, e))
    return merge(list(keep))


def merge(intervals):
    out = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def covered(intervals, s, e, idx):
    """Covered length of [s, e) by sorted disjoint intervals; idx = bisect hint list."""
    import bisect
    i = bisect.bisect_right(idx, s) - 1
    if i < 0:
        i = 0
    total = 0
    while i < len(intervals) and intervals[i][0] < e:
        a, b = intervals[i]
        lo, hi = max(a, s), min(b, e)
        if hi > lo:
            total += hi - lo
        i += 1
    return total


def coarsen(intervals, min_share, min_prefix):
    starts = [a for a, _ in intervals]
    out = []

    def walk(base, plen):
        size = 1 << (32 - plen)
        c = covered(intervals, base, base + size, starts)
        if c == 0:
            return
        if c == size or (c >= min_share * size):
            out.append((base, base + size))
            return
        if plen >= min_prefix:
            return  # small partial piece: stays in the VPN
        walk(base, plen + 1)
        walk(base + size // 2, plen + 1)

    for top in range(256):
        walk(top << 24, 8)
    return merge(out)


def to_cidrs(intervals):
    nets = []
    for s, e in intervals:
        nets.extend(ipaddress.summarize_address_range(ipaddress.IPv4Address(s), ipaddress.IPv4Address(e - 1)))
    return nets


def complement(intervals):
    out, cur = [], 0
    for s, e in intervals:
        if s > cur:
            out.append((cur, s))
        cur = e
    if cur < 2 ** 32:
        out.append((cur, 2 ** 32))
    return out


def size(intervals):
    return sum(e - s for s, e in intervals)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('--out')
    ap.add_argument('--min-share', type=float, default=0.9)
    ap.add_argument('--min-prefix', type=int, default=24)
    ap.add_argument('--stats', action='store_true')
    ap.add_argument('--priority-domains')
    ap.add_argument('--priority-snapshot')
    ap.add_argument('--priority-from-snapshot')
    a = ap.parse_args()
    records = []
    exact, date = load_ru_intervals(a.input, records)
    if a.stats:
        ex = to_cidrs(exact)
        print(f'source date {date}; exact: {len(ex)} cidrs, {size(exact)} addresses, '
              f'complement {len(to_cidrs(complement(exact)))} cidrs')
        for share in (1.0, 0.95, 0.9, 0.8, 0.7, 0.5):
            for mp in (24, 22, 20, 18, 16):
                c = coarsen(exact, share, mp)
                over = size(c) - sum(covered(exact, s, e, [x for x, _ in exact]) for s, e in c)
                lost = size(exact) - (size(c) - over)
                print(f'share>={share:.2f} min_prefix=/{mp}: {len(to_cidrs(c)):5d} cidrs, '
                      f'complement {len(to_cidrs(complement(c))):5d}, '
                      f'foreign-direct {over / size(c) * 100:5.2f}%, ru-via-vpn {lost / size(exact) * 100:5.2f}%')
        return 0
    if not a.out:
        ap.error('--out or --stats required')
    c = coarsen(exact, a.min_share, a.min_prefix)
    nets = to_cidrs(c)
    import json
    priority, resolved = [], {}
    if a.priority_from_snapshot:
        with open(a.priority_from_snapshot, encoding='utf-8') as f:
            resolved = json.load(f)
    elif a.priority_domains:
        with open(a.priority_domains, encoding='utf-8') as f:
            names = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        resolved = resolve_ipv4(names)
        if a.priority_snapshot:
            with open(a.priority_snapshot, 'w', encoding='utf-8', newline='\n') as f:
                json.dump(resolved, f, indent=1, sort_keys=True)
                f.write('\n')
    if resolved:
        addrs = sorted({ip for ips in resolved.values() for ip in ips})
        priority = to_cidrs(priority_records(records, addrs))
        starts = [x for x, _ in exact]
        def russian(ip):
            v = int(ipaddress.IPv4Address(ip))
            return covered(exact, v, v + 1, starts) == 1
        matched = sorted(n for n, ips in resolved.items() if any(russian(i) for i in ips))
        print(f'priority: {len(resolved)} names, {len(matched)} resolved into Russian networks, '
              f'{len(priority)} networks; not Russian/unresolved: '
              + ', '.join(sorted(set(resolved) - set(matched))))
    with open(a.input, 'rb') as f:
        src_sha = hashlib.sha256(f.read()).hexdigest()
    with open(a.out, 'w', encoding='ascii', newline='\n') as f:
        f.write('# Mayak: Russian IPv4 networks (RIPE NCC delegated stats, country RU)\n')
        f.write(f'# source-date {date} source-sha256 {src_sha}\n')
        f.write(f'# min-share {a.min_share} min-prefix {a.min_prefix} entries {len(nets)} priority {len(priority)}\n')
        for n in priority:
            f.write(f'!{n}\n')
        for n in nets:
            f.write(f'{n}\n')
    print(f'{a.out}: {len(nets)} entries (source date {date})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
