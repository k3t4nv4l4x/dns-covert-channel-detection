# DNS Covert Channel Detection (Purple Team Evaluation)

Research project evaluating IDS effectiveness against DNS-based covert communication using a purple team approach.

**Author:** Ketan Vala (Mat. No. 23688958)  
**Program:** MSc ICT, FAU Erlangen-Nurnberg  
**Supervisor:** Dr.-Ing. Loui Al Sardy  
**Module:** Forschungspraktikum (5 ECTS)

## What this project does

Three DNS tunneling scenarios with increasing evasion are tested against three detection approaches in an isolated virtual lab. The result is a 3x3 detection matrix showing where signature-based IDS fails and where statistical scoring picks up the gap.

**Scenarios:**
- S1: iodine tunnel (no evasion, base32 encoding, NULL queries)
- S2: Custom Python C2 with moderate evasion (shorter subdomains, lower frequency)
- S3: Custom Python C2 with high evasion (6-char subdomains, dictionary blending)

**Detection approaches:**
- A: Suricata with 3 custom rules (subdomain length, query frequency, iodine pattern)
- B: Statistical anomaly scorer (S = 0.5H + 0.3F + 0.2U, threshold 0.34)
- C: Hybrid (A OR B, union logic)

## Lab setup

VMware Workstation, VMnet1 Host-Only (192.168.100.0/24):

| VM | Role | IP |
|----|------|----|
| VM1 | Attacker | 192.168.100.1 |
| VM2 | Gateway / Suricata IDS | 192.168.100.2 |
| VM3 | Victim | 192.168.100.3 |

## Repo structure

```
detection/       Scorer and hybrid detection scripts
attack/          C2 client and server (Scenarios 2 and 3)
verification/    Result verification and matrix generation
config/          BIND9 and iptables configuration
data/pcaps/      Packet captures (baseline + 3 scenarios + 2 reruns)
data/suricata_logs/   Suricata eve.json alert logs
data/scorer_output/   Per-domain score CSVs
results/         Final results and reproducibility data
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

|  | Suricata (A) | Scorer (B) | Hybrid (C) |
|--|-------------|-----------|-----------|
| S1 (no evasion) | 100% (3/3 rules) | 100% (S=0.697) | 100% |
| S2 (moderate) | 67% (2/3 rules) | 100% (S=0.391) | 100% |
| S3 (high evasion) | 33% (1/3 rules) | 100% (S=0.387) | 100% |
| Baseline FPR | 0% | 0% | 0% |

Suricata degrades from 100% to 33% rule coverage as evasion increases. The statistical scorer maintains 100% detection across all scenarios. The hybrid approach combines both for full coverage with zero false positives.
