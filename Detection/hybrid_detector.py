#!/usr/bin/env python3
"""
hybrid_detector.py - Hybrid detection combining Suricata alerts with
the statistical anomaly scorer (Approach C).

Logic: a domain is flagged if Suricata raised any alert for it
OR its statistical score meets or exceeds the tuned threshold.
This union-based approach maximises detection coverage because
either detection method catching the attack is sufficient.

Reads:
    - Suricata eve.json log (alert events)
    - Scorer CSV output (per-domain scores from scorer.py)

Produces a combined results CSV showing each domain, whether
Approach A detected it, whether Approach B detected it, the
union result (Approach C), and which rules contributed.

Usage:
    python3 hybrid_detector.py <eve.json> <scores.csv> [--threshold 0.34]

Author: Ketan Vala (23688958)
"""

import sys
import os
import json
import csv
import argparse
from collections import defaultdict


# custom Suricata rules used in this project
CUSTOM_RULES = {
    9000001: "Long subdomain (>20 chars)",
    9000002: "High frequency (>10/min)",
    9000003: "iodine pattern match",
}


def parse_eve_alerts(eve_path):
    """
    Read Suricata eve.json and extract alert events.

    Returns a dict mapping each queried domain to a dict of
    {signature_id: alert_count}.  Only custom rules (SID 9000001-9000003)
    are counted; built-in rules like ICMP ping are ignored because
    they are not part of the DNS tunnel detection rule set.
    """
    domain_alerts = defaultdict(lambda: defaultdict(int))
    total_custom = 0

    with open(eve_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            if ev.get("event_type") != "alert":
                continue

            sid = ev.get("alert", {}).get("signature_id", 0)
            if sid not in CUSTOM_RULES:
                continue

            # extract domain from the DNS query attached to the alert
            # Suricata eve.json nests this under dns.queries[0].rrname
            qname = ""
            dns_info = ev.get("dns", {})
            queries = dns_info.get("queries", [])
            if queries:
                qname = queries[0].get("rrname", "")
            if not qname:
                # older format might use dns.query directly
                qname = dns_info.get("query", "")
            if not qname:
                continue  # skip alerts without DNS context

            # normalise: strip trailing dot, extract base domain
            qname = qname.rstrip(".")
            parts = qname.split(".")
            if len(parts) >= 2:
                base_domain = ".".join(parts[-2:])
            else:
                base_domain = qname

            domain_alerts[base_domain][sid] += 1
            total_custom += 1

    return domain_alerts, total_custom


def parse_scorer_csv(csv_path):
    """
    Read the per-domain CSV produced by scorer.py.

    Returns a dict mapping domain name to its score (float).
    """
    scores = {}
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row["domain"]
            score = float(row["score_S"])
            scores[domain] = score
    return scores


def compute_hybrid(domain_alerts, scorer_results, threshold):
    """
    Apply union logic: flag a domain if Suricata detected it OR
    the scorer flagged it.

    Returns a list of dicts, one per domain, with:
        domain, score_S, above_threshold (bool), suricata_detected (bool),
        rules_fired (list of SIDs), alert_count, hybrid_detected (bool),
        detection_source
    """
    # collect all domains seen by either method
    all_domains = set(scorer_results.keys())
    all_domains.update(domain_alerts.keys())

    results = []

    for domain in sorted(all_domains):
        score = scorer_results.get(domain, 0.0)
        above_threshold = score >= threshold

        alerts = domain_alerts.get(domain, {})
        rules_fired = sorted(alerts.keys())
        alert_count = sum(alerts.values())
        suricata_hit = alert_count > 0

        # union logic: either one detecting is enough
        hybrid_hit = suricata_hit or above_threshold

        if suricata_hit and above_threshold:
            source = "Both A and B"
        elif suricata_hit:
            source = "A only (Suricata)"
        elif above_threshold:
            source = "B only (Scorer)"
        else:
            source = "Neither"

        results.append({
            "domain": domain,
            "score_S": round(score, 4),
            "above_threshold": above_threshold,
            "suricata_detected": suricata_hit,
            "rules_fired": "/".join(str(s) for s in rules_fired),
            "alert_count": alert_count,
            "hybrid_detected": hybrid_hit,
            "detection_source": source,
        })

    return results


def rules_tpr(domain_alerts):
    """
    Compute per-rule and overall Approach A TPR.

    TPR is defined as the fraction of the 3 custom rules that fired
    at least once.  This matches the 3x3 matrix definition: each
    rule either contributed or it did not.
    """
    fired = set()
    for alerts_by_sid in domain_alerts.values():
        fired.update(alerts_by_sid.keys())

    rules_fired = len(fired.intersection(CUSTOM_RULES.keys()))
    total_rules = len(CUSTOM_RULES)
    tpr = rules_fired / total_rules if total_rules > 0 else 0.0
    return rules_fired, total_rules, tpr, fired


def save_hybrid_csv(results, output_path, scenario_label=""):
    """Write hybrid detection results to CSV."""
    header = [
        "domain", "score_S", "above_threshold", "suricata_detected",
        "rules_fired", "alert_count", "hybrid_detected", "detection_source",
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="Hybrid DNS covert channel detection (Approach C)")
    parser.add_argument("eve_json", help="Suricata eve.json log file")
    parser.add_argument("scores_csv", help="Scorer CSV from scorer.py")
    parser.add_argument("--threshold", type=float, default=0.34,
                        help="Detection threshold (default: 0.34)")
    parser.add_argument("--output", default="",
                        help="Output CSV path (default: hybrid_<scenario>.csv)")
    parser.add_argument("--label", default="",
                        help="Scenario label for output naming")
    args = parser.parse_args()

    threshold = args.threshold

    # parse both data sources
    domain_alerts, total_custom = parse_eve_alerts(args.eve_json)
    scorer_results = parse_scorer_csv(args.scores_csv)

    # Approach A summary
    rules_count, total_rules, a_tpr, fired_sids = rules_tpr(domain_alerts)

    print("=" * 60)
    print("  HYBRID DETECTION ANALYSIS (Approach C)")
    print("=" * 60)

    print(f"\n  Suricata log: {args.eve_json}")
    print(f"  Scorer CSV:   {args.scores_csv}")
    print(f"  Threshold:    {threshold}")

    # Approach A breakdown
    print(f"\n  --- Approach A (Suricata) ---")
    print(f"  Custom rule alerts: {total_custom}")
    print(f"  Rules fired: {rules_count}/{total_rules} "
          f"(TPR = {a_tpr:.1%})")
    for sid, desc in sorted(CUSTOM_RULES.items()):
        total_for_sid = sum(
            alerts.get(sid, 0) for alerts in domain_alerts.values()
        )
        status = "FIRED" if sid in fired_sids else "not fired"
        print(f"    SID {sid} ({desc}): {total_for_sid} alerts [{status}]")

    # Approach B breakdown
    print(f"\n  --- Approach B (Scorer) ---")
    detected_b = [d for d, s in scorer_results.items() if s >= threshold]
    missed_b = [d for d, s in scorer_results.items() if s < threshold]
    print(f"  Domains scored: {len(scorer_results)}")
    print(f"  Detected (score >= {threshold}): {len(detected_b)}")
    for d in detected_b:
        margin = scorer_results[d] - threshold
        print(f"    {d}: {scorer_results[d]:.4f} (margin +{margin:.4f})")

    # Approach C (hybrid)
    hybrid_results = compute_hybrid(domain_alerts, scorer_results, threshold)

    detected_c = [r for r in hybrid_results if r["hybrid_detected"]]
    print(f"\n  --- Approach C (Hybrid = A OR B) ---")
    print(f"  Domains evaluated: {len(hybrid_results)}")
    print(f"  Detected: {len(detected_c)}")
    for r in detected_c:
        print(f"    {r['domain']}: {r['detection_source']}")

    # Approach C TPR: did the hybrid detect the attack domain?
    # The attack domain is the one present in the scorer CSV (c2.lab
    # or tunnel.lab).  Hybrid detects it if A or B detected it.
    attack_detected = any(
        r["hybrid_detected"] for r in hybrid_results
        if r["domain"] in scorer_results
    )
    c_tpr = 1.0 if attack_detected else 0.0

    # detection source for the attack domain
    attack_source = "Neither"
    for r in hybrid_results:
        if r["domain"] in scorer_results and r["hybrid_detected"]:
            attack_source = r["detection_source"]

    print(f"\n  --- Summary for 3x3 Matrix ---")
    print(f"  Approach A TPR: {a_tpr:.1%} ({rules_count}/{total_rules} rules)")
    b_detected = any(s >= threshold for s in scorer_results.values())
    print(f"  Approach B TPR: {'100.0%' if b_detected else '0.0%'}")
    print(f"  Approach C TPR: {c_tpr:.1%}")
    print(f"  Approach C source: {attack_source}")

    # save CSV
    if args.output:
        out_path = args.output
    else:
        label = args.label or os.path.splitext(
            os.path.basename(args.scores_csv))[0]
        out_path = f"hybrid_{label}.csv"

    save_hybrid_csv(hybrid_results, out_path)
    print(f"\n  Saved: {out_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
