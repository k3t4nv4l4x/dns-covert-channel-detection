#!/usr/bin/env python3
"""
scorer.py - Statistical anomaly scorer for DNS covert channel detection.

Analyses a PCAP file and scores each observed domain based on three
features: Shannon entropy of subdomain strings, normalised query
frequency, and unique subdomain ratio. A composite weighted score
determines whether the domain is flagged as suspicious.

Scoring formula:
    S = 0.5 * H + 0.3 * F + 0.2 * U

where
    H = avg Shannon entropy of subdomains, normalised by log2(36)
    F = queries per minute / 60
    U = unique subdomains / total queries

Threshold is tuned on the baseline PCAP: it is set to the smallest
value (in 0.01 steps) above the highest baseline score, ensuring
0% false positive rate on the baseline while staying as sensitive
as possible.

Usage:
    python3 scorer.py baseline.pcap scenario1.pcap [scenario2.pcap ...]

The first argument is always the baseline, used for threshold tuning.
All subsequent arguments are scored against that threshold.

Requirements:
    pip install scapy

Author: Ketan Vala (23688958)
"""

import sys
import os
import csv
import math
from collections import Counter, defaultdict
from scapy.all import rdpcap, DNS, DNSQR

# --- weights for the composite score ---
W_ENTROPY = 0.5
W_FREQUENCY = 0.3
W_UNIQUE = 0.2

# normalisation constants
ENTROPY_NORM = math.log2(36)  # 36 valid DNS label chars: a-z + 0-9
FREQ_NORM = 60.0              # queries per minute cap


def shannon_entropy(s):
    """Shannon entropy of a string, in bits."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_domains(pcap_path):
    """
    Parse DNS queries from a PCAP and group by second-level domain.

    For each query, we extract the immediate subdomain label (the first
    label before the base domain) and normalise it to lowercase.  This
    gives consistent results regardless of case-varying encodings like
    iodine's base128, and avoids inflating length/entropy when a query
    name has multiple subdomain levels (e.g. a.b.example.com).

    Returns a dict mapping each domain to a list of
    (subdomain_label, timestamp) tuples.
    """
    packets = rdpcap(pcap_path)
    domains = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            continue
        if pkt[DNS].qr != 0:
            continue

        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        parts = qname.split(".")

        # need at least sub.domain.tld to have a subdomain
        if len(parts) < 3:
            continue

        domain = ".".join(parts[-2:])
        subdomain = parts[0].lower()  # first label, case-normalised
        ts = float(pkt.time)
        domains[domain].append((subdomain, ts))

    return domains


def score_domain(entries):
    """
    Compute the three features and composite score for one domain.

    Parameters
    ----------
    entries : list of (subdomain, timestamp) tuples

    Returns
    -------
    dict with keys: queries, avg_length, entropy_H, frequency_F,
                    unique_U, score_S, qpm
    """
    subdomains = [e[0] for e in entries]
    timestamps = [e[1] for e in entries]
    total = len(subdomains)

    # --- entropy feature ---
    entropies = [shannon_entropy(s) for s in subdomains if s]
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    h_norm = avg_entropy / ENTROPY_NORM

    # --- frequency feature ---
    if len(timestamps) > 1:
        duration_min = (max(timestamps) - min(timestamps)) / 60.0
        qpm = total / duration_min if duration_min > 0 else 0.0
    else:
        qpm = 0.0
    f_norm = min(qpm / FREQ_NORM, 1.0)  # cap at 1.0

    # --- unique ratio feature ---
    unique_count = len(set(subdomains))
    u_ratio = unique_count / total if total > 0 else 0.0

    # --- composite ---
    score = W_ENTROPY * h_norm + W_FREQUENCY * f_norm + W_UNIQUE * u_ratio

    avg_len = sum(len(s) for s in subdomains) / total if total > 0 else 0.0

    return {
        "queries": total,
        "avg_length": round(avg_len, 1),
        "entropy_H": round(h_norm, 4),
        "frequency_F": round(f_norm, 4),
        "unique_U": round(u_ratio, 4),
        "score_S": round(score, 4),
        "qpm": round(qpm, 1),
    }


def tune_threshold(domain_scores, target_fpr=0.05):
    """
    Set threshold just above the highest baseline score.

    We round up the maximum baseline score to the next 0.01 boundary.
    This gives 0% FPR on the baseline while keeping the threshold as
    low as possible for maximum sensitivity.

    Falls back to a sweep from 0.90 downward if many domains score
    high and a tighter threshold is needed to meet the target FPR.
    """
    scores = [v["score_S"] for v in domain_scores.values()]
    total = len(scores)
    if total == 0:
        return 0.34, 0.0

    max_score = max(scores)
    # round up to next 0.01
    threshold = math.ceil(max_score * 100) / 100

    flagged = sum(1 for s in scores if s >= threshold)
    fpr = flagged / total

    if fpr <= target_fpr:
        return round(threshold, 2), round(fpr, 4)

    # fallback: sweep downward from 0.90
    threshold = 0.90
    while threshold > 0.0:
        flagged = sum(1 for s in scores if s >= threshold)
        fpr = flagged / total
        if fpr <= target_fpr:
            return round(threshold, 2), round(fpr, 4)
        threshold -= 0.01

    return 0.01, 1.0


def analyse_pcap(pcap_path):
    """Score all domains found in one PCAP file."""
    domains = extract_domains(pcap_path)
    results = {}
    for domain, entries in domains.items():
        results[domain] = score_domain(entries)
    return results


def save_csv(results, output_path, label=""):
    """Write per-domain scores to a CSV file."""
    header = [
        "domain", "queries", "avg_length", "entropy_H",
        "frequency_F", "unique_U", "score_S", "qpm", "label",
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for domain in sorted(results, key=lambda d: results[d]["score_S"],
                             reverse=True):
            row = {"domain": domain, "label": label}
            row.update(results[domain])
            writer.writerow(row)


def print_results(results, name, threshold=None):
    """Print a formatted summary of scored domains."""
    print(f"\n  Analysing: {name}")
    print(f"  Domains found: {len(results)}")

    if not results:
        print("  No DNS queries found.")
        return

    # sort by score descending
    ranked = sorted(results.items(), key=lambda x: x[1]["score_S"],
                    reverse=True)

    print("\n  Top scored domains:")
    header = f"  {'domain':<20} {'queries':>7} {'avg_length':>10} "
    header += f"{'entropy_H':>10} {'frequency_F':>12} {'unique_U':>8} {'score_S':>8}"
    print(header)

    for domain, vals in ranked[:10]:
        line = f"  {domain:<20} {vals['queries']:>7} {vals['avg_length']:>10} "
        line += f"{vals['entropy_H']:>10} {vals['frequency_F']:>12} "
        line += f"{vals['unique_U']:>8} {vals['score_S']:>8}"
        print(line)

        if threshold is not None:
            flag = " << DETECTED" if vals["score_S"] >= threshold else ""
            if flag:
                print(f"    ^ score {vals['score_S']} >= threshold {threshold}{flag}")


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <baseline.pcap> <scenario.pcap> [...]")
        sys.exit(1)

    baseline_path = sys.argv[1]
    scenario_paths = sys.argv[2:]

    # ---- step 1: score the baseline ----
    print("=" * 65)
    print("  BASELINE ANALYSIS")
    print("=" * 65)

    baseline_scores = analyse_pcap(baseline_path)
    print_results(baseline_scores, baseline_path)

    # determine output directory from first scenario path
    out_dir = os.path.dirname(os.path.abspath(scenario_paths[0]))
    results_dir = os.path.join(out_dir, "results")
    os.makedirs(results_dir, exist_ok=True)

    save_csv(baseline_scores,
             os.path.join(results_dir, "scores_baseline.csv"), label="normal")
    print(f"  Saved: {os.path.join(results_dir, 'scores_baseline.csv')}")

    # ---- step 2: tune threshold on baseline ----
    threshold, fpr = tune_threshold(baseline_scores)

    print("\n" + "=" * 65)
    print("  THRESHOLD TUNING ON BASELINE")
    print("=" * 65)
    print(f"\n  Threshold tuned: {threshold}")
    print(f"  Baseline FPR at this threshold: {fpr:.4f} ({fpr*100:.1f}%)")
    print(f"  Target FPR: 0.05 (5%)")
    if fpr <= 0.05:
        print("  ✓ FPR is within target")
    else:
        print("  ✗ FPR exceeds target")

    # ---- step 3: score each scenario ----
    for spath in scenario_paths:
        scenario_name = os.path.splitext(os.path.basename(spath))[0]

        print("\n" + "-" * 65)
        print(f"  Processing: {scenario_name} (attack)")
        print("-" * 65)

        sc_scores = analyse_pcap(spath)
        print_results(sc_scores, spath, threshold=threshold)

        csv_name = f"scores_{scenario_name}.csv"
        csv_path = os.path.join(results_dir, csv_name)
        save_csv(sc_scores, csv_path, label="attack")
        print(f"  Saved: {csv_path}")

        # per-scenario detection summary
        detected = sum(1 for v in sc_scores.values()
                       if v["score_S"] >= threshold)
        total = len(sc_scores)
        tpr = detected / total if total > 0 else 0.0
        margin = max((v["score_S"] - threshold)
                     for v in sc_scores.values()) if sc_scores else 0.0

        print(f"\n  Detection: {detected}/{total} domains above threshold")
        print(f"  TPR: {tpr:.1%}")
        print(f"  Max margin above threshold: +{margin:.4f}")

    print("\n" + "=" * 65)
    print("  Done.")
    print("=" * 65)


if __name__ == "__main__":
    main()
