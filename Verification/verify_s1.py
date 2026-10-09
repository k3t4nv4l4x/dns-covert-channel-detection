#!/usr/bin/env python3
"""
verify_s1.py - Verify Scenario 1 (iodine) traffic characteristics from PCAP.

Parses DNS queries to the tunnel domain and computes:
  - Total query count
  - Average subdomain length and Shannon entropy
  - Query rate (queries per minute)
  - DNS query type distribution

Usage:
    python3 verify_s1.py scenario1.pcap

Requirements:
    pip install scapy

Author: Ketan Vala (23688958)
"""

import sys
import math
from collections import Counter
from scapy.all import rdpcap, DNS, DNSQR, IP


TUNNEL_DOMAIN = "tunnel.lab"


def shannon_entropy(s):
    """Calculate Shannon entropy of a string in bits."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def get_subdomain(qname, domain):
    """Strip tunnel domain suffix to extract encoded subdomain."""
    qname = qname.rstrip(".")
    suffix = "." + domain.rstrip(".")
    if qname.lower().endswith(suffix.lower()):
        return qname[: -len(suffix)]
    return qname


def main(pcap_path):
    packets = rdpcap(pcap_path)
    dns_type_names = {1: "A", 5: "CNAME", 10: "NULL", 16: "TXT", 28: "AAAA"}

    subdomains = []
    timestamps = []
    qtypes = Counter()

    for pkt in packets:
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            continue
        if pkt[DNS].qr != 0:  # skip responses
            continue

        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        if not qname.lower().endswith(TUNNEL_DOMAIN):
            continue

        subdomain = get_subdomain(qname, TUNNEL_DOMAIN)
        subdomains.append(subdomain)
        timestamps.append(float(pkt.time))
        qtypes[pkt[DNSQR].qtype] += 1

    if not subdomains:
        print("No tunnel queries found.")
        sys.exit(1)

    # Compute metrics
    total = len(subdomains)
    lengths = [len(s) for s in subdomains]
    avg_len = sum(lengths) / total
    entropies = [shannon_entropy(s) for s in subdomains]
    avg_ent = sum(entropies) / total

    duration_min = (max(timestamps) - min(timestamps)) / 60.0
    qps = total / duration_min if duration_min > 0 else 0

    # Print results
    print("=" * 55)
    print("SCENARIO 1 (iodine) - VERIFICATION")
    print("=" * 55)
    print(f"  PCAP:               {pcap_path}")
    print(f"  Tunnel domain:      {TUNNEL_DOMAIN}")
    print(f"  Total queries:      {total}")
    print(f"  Avg subdomain len:  {avg_len:.1f} chars")
    print(f"  Avg entropy:        {avg_ent:.3f} bits")
    print(f"  Capture duration:   {duration_min:.1f} min")
    print(f"  Queries/min:        {qps:.1f}")
    print(f"  Query types:")
    for qt, count in qtypes.most_common():
        name = dns_type_names.get(qt, f"TYPE{qt}")
        print(f"    {name} (type {qt}): {count}")
    print("=" * 55)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    main(sys.argv[1])
