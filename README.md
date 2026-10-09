# DNS Covert Channel Detection (Purple Team Evaluation)

This project tests how well an IDS detects DNS-based covert communication when attackers apply increasing levels of evasion. It uses a purple team setup where the same operator runs both the attack and the detection, then compares results across a 3x3 evaluation matrix.

Author: Ketan Vala (Mat. No. 23688958)  
Program: MSc ICT, FAU Erlangen-Nurnberg  
Supervisor: Dr.-Ing. Loui Al Sardy  
Module: Forschungspraktikum (5 ECTS)

## Overview

Three DNS tunneling scenarios are tested against three detection approaches in an isolated virtual lab. Each scenario encodes data in DNS subdomain labels but applies different evasion techniques, from none (raw iodine) to high (short labels blended with dictionary words).

Scenarios:
- S1: iodine tunnel, no evasion, base32 encoding, NULL query type
- S2: Custom Python C2 with moderate evasion (shorter subdomains, lower query rate, TXT type)
- S3: Custom Python C2 with high evasion (6-char subdomains, dictionary blending, TXT type)

Detection approaches:
- A: Suricata IDS with 3 custom rules (SID 9000001: subdomain length >20 chars, SID 9000002: query frequency >10/min, SID 9000003: iodine pattern match)
- B: Statistical anomaly scorer using weighted features: S = 0.5H + 0.3F + 0.2U, where H is normalised Shannon entropy, F is normalised query frequency, and U is the unique subdomain ratio. Threshold is 0.34, tuned on baseline traffic with 0% FPR.
- C: Hybrid detection using union logic (flag if A OR B detects)

## Lab setup

VMware Workstation with a VMnet1 Host-Only network (192.168.100.0/24):

| VM | Role | IP |
|----|------|----|
| VM1 | Attacker | 192.168.100.1 |
| VM2 | Gateway / Suricata IDS | 192.168.100.2 |
| VM3 | Victim | 192.168.100.3 |

## Repo structure

```
detection/            Scorer and hybrid detection scripts
attack/               C2 client and server (Scenarios 2 and 3)
verification/         Result verification and matrix generation
config/               BIND9 and iptables configuration
data/pcaps/           Packet captures (baseline + 3 scenarios + 2 reruns)
data/suricata_logs/   Suricata eve.json alert logs
data/scorer_output/   Per-domain score CSVs
results/              Final results and reproducibility data
```

## How to run

Scorer (needs scapy):
```bash
pip install scapy
python3 detection/scorer.py data/pcaps/baseline.pcap data/pcaps/scenario1.pcap
```

Hybrid detector:
```bash
python3 detection/hybrid_detector.py data/suricata_logs/eve_s1.json data/scorer_output/scores_scenario1.csv
```

Verify S1 traffic:
```bash
python3 verification/verify_s1.py data/pcaps/scenario1.pcap
```

Generate full results matrix:
```bash
python3 verification/final_matrix.py
```

## Key results

### 3x3 detection matrix

|  | Suricata (A) | Scorer (B) | Hybrid (C) |
|--|-------------|-----------|-----------|
| S1 (no evasion) | 100% (3/3 rules, 1471 alerts) | 100% (S=0.697, margin +0.357) | 100% |
| S2 (moderate) | 67% (2/3 rules, 10 alerts) | 100% (S=0.391, margin +0.051) | 100% |
| S3 (high evasion) | 33% (1/3 rules, 8 alerts) | 100% (S=0.387, margin +0.047) | 100% |
| Baseline FPR | 0% | 0% | 0% |

Suricata rule coverage drops from 3/3 to 1/3 as evasion increases. The scorer detected all three scenarios, though S3 had a margin of only +0.047 above threshold, which is 0.049 above the highest baseline domain (cloudfront.net at 0.338). The hybrid approach (union of A and B) achieved 100% detection in every cell with 0% false positives.

### Traffic characteristics

| Metric | Baseline | S1 (iodine) | S2 (moderate) | S3 (high evasion) |
|--------|----------|-------------|---------------|--------------------|
| Total queries | 507 | 1449 | 68 | 210 |
| Avg subdomain length | 6.8 chars | 33.5 chars | 20.9 chars | 6.0 chars |
| Shannon entropy | ~2.4 | 3.569 | 3.575 | 2.410 |
| Queries/min | 13.3 | 170.1 | 6.8 | 21.2 |
| Unique domains | 28 | - | - | - |
| DNS query type | A | NULL | TXT | TXT |

### Scorer feature breakdown

| Domain | H (entropy) | F (frequency) | U (unique ratio) | S (score) |
|--------|------------|---------------|-------------------|-----------|
| cloudfront.net (baseline max) | 0.645 | 0.008 | 0.067 | 0.338 |
| tunnel.lab (S1) | 0.619 | 1.000 | 0.438 | 0.697 |
| c2.lab (S2) | 0.692 | 0.113 | 0.059 | 0.391 |
| c2.lab (S3) | 0.466 | 0.354 | 0.238 | 0.387 |

The threshold (0.34) was set by rounding up the highest baseline score (0.338) to the next 0.01 step. This gave 0% FPR while keeping sensitivity as high as possible.

### Per-rule detail

| Rule (SID) | S1 | S2 | S3 |
|------------|----|----|-----|
| 9000001: subdomain >20 chars | Fired (4 alerts) | Fired (8 alerts) | Not fired |
| 9000002: frequency >10/min | Fired (18 alerts) | Fired (2 alerts) | Fired (8 alerts) |
| 9000003: iodine pattern | Fired (1449 alerts) | Not fired | Not fired |

In S3, only the frequency rule fired. The length rule missed because S3 uses 6-character subdomains, and the iodine rule missed because S3 uses a custom C2 protocol. Suricata still detected the tunnel (at least one rule fired), but rule coverage dropped to 33%.

### Reproducibility (Run 2)

| Scenario | Approach A | Approach B score | Approach B margin |
|----------|-----------|-----------------|-------------------|
| S2 Run 2 | 67% (2/3 rules, 32 alerts) | 0.418 | +0.078 |
| S3 Run 2 | 33% (1/3 rules, 10 alerts) | 0.413 | +0.073 |

Detection outcomes were identical between runs. Deterministic features (entropy, unique ratio) varied less than 2%. Timing-dependent features (frequency) varied 15-28% between runs, but not enough to change any detection decision.

### Evasion trade-off

Reducing subdomain length to evade the length rule (SID 9000001) forces the attacker to send more queries to transmit the same data. This amplifies the frequency signal and keeps the scorer above threshold. The S3 detection margin of +0.047 is narrow, but the trade-off between length and frequency means the attacker cannot reduce both simultaneously without losing channel capacity.
