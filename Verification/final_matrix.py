#!/usr/bin/env python3
"""
Final Results Matrix — Primary Research Output
Project: A Purple Team Evaluation of IDS Effectiveness
         Against DNS-Based Covert Communication
Student: Ketan Vala | 23688958
Supervisor: Dr.-Ing. Loui Al Sardy
"""
import pandas as pd
import os

RESULTS_DIR = r"E:\ResearchProject\results"
# UPDATE THIS PATH if different:
# RESULTS_DIR = r"C:\DNS_Project\results"
os.makedirs(RESULTS_DIR, exist_ok=True)

print(f"{'='*75}")
print(f"FINAL 3×3 EVALUATION MATRIX — PRIMARY RESEARCH RESULT")
print(f"Project: A Purple Team Evaluation of IDS Effectiveness")
print(f"         Against DNS-Based Covert Communication")
print(f"Student: Ketan Vala | 23688958")
print(f"{'='*75}")


# ══════════════════════════════════════════════════════════════
# SECTION 1: TRAFFIC CHARACTERISTICS
# ══════════════════════════════════════════════════════════════

print(f"\n{'='*75}")
print(f"SECTION 1 — TRAFFIC CHARACTERISTICS (All Verified)")
print(f"{'='*75}")

print(f"""
  ┌──────────────────┬──────────┬──────────┬──────────┬──────────┐
  │ Metric           │ Baseline │ S1       │ S2       │ S3       │
  │                  │ (Normal) │ (iodine) │ (Custom) │ (Mimicry)│
  ├──────────────────┼──────────┼──────────┼──────────┼──────────┤
  │ Queries          │ 507      │ 1449     │ 68       │ 210      │
  │ Avg sub length   │ 6.8      │ 21.3     │ 20.9     │ 6.0      │
  │ Avg entropy      │ ~2.3     │ 3.199    │ 3.575    │ 2.410    │
  │ Queries/min      │ 13.3     │ 170.1    │ 6.8      │ 21.2     │
  │ Query type       │ A        │ NULL     │ TXT      │ TXT      │
  │ Duration         │ 38 min   │ 8.5 min  │ 10 min   │ 9.9 min  │
  └──────────────────┴──────────┴──────────┴──────────┴──────────┘
""")


# ══════════════════════════════════════════════════════════════
# SECTION 2: APPROACH A — SURICATA SIGNATURE RULES
# ══════════════════════════════════════════════════════════════

print(f"{'='*75}")
print(f"SECTION 2 — APPROACH A: Suricata Signature Rules")
print(f"{'='*75}")

print(f"""
  Rules deployed:
    SID 9000001: Subdomain length > 20 characters
    SID 9000002: Query frequency > 10 queries per 60 seconds
    SID 9000003: iodine tool pattern match

  ┌──────────────────────────┬───────────┬───────────┬───────────┐
  │ Rule                     │ S1        │ S2        │ S3        │
  ├──────────────────────────┼───────────┼───────────┼───────────┤
  │ Rule 1 (length >20)      │ ✓ FIRED   │ ✓ FIRED   │ ✗ MISSED  │
  │ Rule 2 (freq >10/min)    │ ✓ FIRED   │ ✓ FIRED   │ ✓ FIRED   │
  │ Rule 3 (iodine pattern)  │ ✓ FIRED   │ ✗ MISSED  │ ✗ MISSED  │
  ├──────────────────────────┼───────────┼───────────┼───────────┤
  │ Rules fired              │ 3/3       │ 2/3       │ 1/3       │
  │ Total alerts             │ 1471      │ 10        │ 8         │
  │ TPR(A)                   │ 100%      │ 67%       │ 33%       │
  └──────────────────────────┴───────────┴───────────┴───────────┘
  
  Baseline FPR(A): 0% (zero false alerts on normal traffic)

  WHY EACH RULE FAILS:
    Rule 1 fails on S3: mimicry reduces subdomains to 6 chars
      (baseline median), eliminating the length signal entirely.
    Rule 3 fails on S2+S3: custom Python agent has no iodine-
      specific encoding patterns — no signature to match.
    Rule 2 survives on S3: chunking splits each message into
      multiple queries, increasing rate to 21.2/min (above 10/min
      threshold). Mimicry creates an evasion TRADE-OFF.

  DEGRADATION: 100% → 67% → 33%
""")


# ══════════════════════════════════════════════════════════════
# SECTION 3: APPROACH B — STATISTICAL SCORER
# ══════════════════════════════════════════════════════════════

print(f"{'='*75}")
print(f"SECTION 3 — APPROACH B: Statistical Anomaly Scorer")
print(f"{'='*75}")

print(f"""
  Formula: S = 0.5H + 0.3F + 0.2U
  Threshold: θ = 0.34 (tuned on baseline, FPR = 0%)

  ┌──────────────────┬──────────┬──────────┬──────────┬──────────┐
  │ Feature          │ Baseline │ S1       │ S2       │ S3       │
  │                  │ (max)    │ (iodine) │ (Custom) │ (Mimicry)│
  ├──────────────────┼──────────┼──────────┼──────────┼──────────┤
  │ Entropy (H)      │ 0.645    │ 0.619    │ 0.692    │ 0.466    │
  │ Frequency (F)    │ 0.008    │ 1.000    │ 0.113    │ 0.354    │
  │ Unique (U)       │ 0.067    │ 0.438    │ 0.059    │ 0.238    │
  ├──────────────────┼──────────┼──────────┼──────────┼──────────┤
  │ Score (S)        │ 0.338    │ 0.697    │ 0.391    │ 0.387    │
  │ Margin from θ    │ -0.002   │ +0.357   │ +0.051   │ +0.047   │
  │ Detected         │ ✓ BELOW  │ ✓ ABOVE  │ ✓ ABOVE  │ ✓ ABOVE  │
  │ TPR(B)           │ —        │ 100%     │ 100%     │ 100%     │
  └──────────────────┴──────────┴──────────┴──────────┴──────────┘

  Baseline FPR(B): 0% (all 5 baseline domains below θ)
  
  Baseline domain scores:
    cloudfront.net:  0.338  ← highest (CDN subdomains)
    microsoft.com:   0.254
    akamaiedge.net:  0.247
    ubuntu.com:      0.180
    amazon.com:      0.169

  MARGIN DEGRADATION: +0.357 → +0.051 → +0.047 (87% reduction)

  WHY S3 IS STILL DETECTED:
    Mimicry reduced entropy by 33% (H: 0.692 → 0.466).
    BUT chunking increased frequency by 3× (F: 0.113 → 0.354).
    The trade-off partially cancelled the evasion benefit.
    Net score reduction: only 0.004 (0.391 → 0.387).
""")


# ══════════════════════════════════════════════════════════════
# SECTION 4: APPROACH C — HYBRID DETECTION
# ══════════════════════════════════════════════════════════════

print(f"{'='*75}")
print(f"SECTION 4 — APPROACH C: Hybrid Detection (A OR B)")
print(f"{'='*75}")

print(f"""
  Decision rule: flag if Suricata alert OR scorer ≥ 0.34

  ┌──────────────────┬───────────┬───────────┬───────────┐
  │ Component        │ S1        │ S2        │ S3        │
  ├──────────────────┼───────────┼───────────┼───────────┤
  │ A detected?      │ ✓ YES     │ ✓ YES     │ ✓ YES     │
  │ B detected?      │ ✓ YES     │ ✓ YES     │ ✓ YES     │
  │ C detected?      │ ✓ YES     │ ✓ YES     │ ✓ YES     │
  │ Source           │ Both A+B  │ Both A+B  │ Both A+B  │
  │ TPR(C)           │ 100%      │ 100%      │ 100%      │
  └──────────────────┴───────────┴───────────┴───────────┘

  Baseline FPR(C): 0%

  WHY HYBRID PROVIDES DEFENCE-IN-DEPTH:
    On S3: A catches via frequency (chunking trade-off)
           B catches via entropy + unique ratio
    These are INDEPENDENT detection signals.
    An attacker must defeat BOTH simultaneously.
""")


# ══════════════════════════════════════════════════════════════
# SECTION 5: FINAL 3×3 MATRIX
# ══════════════════════════════════════════════════════════════

print(f"{'='*75}")
print(f"SECTION 5 — FINAL 3×3 RESULTS MATRIX")
print(f"{'='*75}")

print(f"""
  ┌────────────────────┬─────────────────┬─────────────────┬─────────────────┐
  │                    │  Approach A      │  Approach B      │  Approach C      │
  │    Scenario        │  Suricata Rules  │  Scorer          │  Hybrid (A|B)    │
  ├────────────────────┼─────────────────┼─────────────────┼─────────────────┤
  │ S1 (Low Evasion)   │ 100% (3/3)      │ 100% (S=0.697)  │ 100%            │
  │ S2 (Medium Evasion)│  67% (2/3)      │ 100% (S=0.391)  │ 100%            │
  │ S3 (High Evasion)  │  33% (1/3)      │ 100% (S=0.387)  │ 100%            │
  ├────────────────────┼─────────────────┼─────────────────┼─────────────────┤
  │ Baseline FPR       │  0%             │  0%              │  0%             │
  └────────────────────┴─────────────────┴─────────────────┴─────────────────┘

  Threshold (θ): 0.34  |  Scorer: S = 0.5H + 0.3F + 0.2U
""")


# ══════════════════════════════════════════════════════════════
# SECTION 6: REPRODUCIBILITY VERIFICATION
# ══════════════════════════════════════════════════════════════

print(f"{'='*75}")
print(f"SECTION 6 — REPRODUCIBILITY VERIFICATION")
print(f"{'='*75}")

print(f"""
  Each scenario repeated twice. Detection outcomes compared.

  ┌────────────┬────────────────────┬────────────────────┬──────────┐
  │            │ Approach A         │ Approach B         │ Match?   │
  │ Scenario   │ Run 1 → Run 2      │ Run 1 → Run 2      │          │
  ├────────────┼────────────────────┼────────────────────┼──────────┤
  │ S2 (custom)│ 67% → 67%          │ 0.391 → 0.418      │ ✓ YES    │
  │ S3 (mimic) │ 33% → 33%          │ 0.387 → 0.413      │ ✓ YES    │
  └────────────┴────────────────────┴────────────────────┴──────────┘

  S2 Reproducibility: 6/7 metrics within ±20% → REPRODUCIBLE
  S3 Reproducibility: 4/7 metrics within ±20% → PARTIALLY REPRODUCIBLE

  Variance explanation:
    Deterministic features (subdomain length, entropy) vary < 2%
    Stochastic features (query count, frequency) vary 15-28%
    Variance is due to randomised agent timing (5-30s intervals)
    Detection OUTCOMES are identical across all runs
""")


# ══════════════════════════════════════════════════════════════
# SECTION 7: HYPOTHESIS VERIFICATION
# ══════════════════════════════════════════════════════════════

print(f"{'='*75}")
print(f"SECTION 7 — HYPOTHESIS VERIFICATION")
print(f"{'='*75}")

print(f"""
  H1: "Approach A will achieve >90% TPR on S1 but degrade
       below 50% on S3"
  
  RESULT: S1 = 100%, S2 = 67%, S3 = 33%
  VERDICT: ✓ CONFIRMED
    S1 exceeds 90% (100%)
    S3 is below 50% (33%)
    Clear degradation pattern: 100% → 67% → 33%

  ──────────────────────────────────────────────────────────

  H2: "Approach B will maintain detection across all scenarios
       but detection margin will shrink as evasion increases"
  
  RESULT: TPR = 100% all scenarios
          Margin: +0.357 → +0.051 → +0.047 (87% reduction)
  VERDICT: ✓ CONFIRMED
    Detection maintained at 100% across all scenarios
    Margin degrades from +0.357 (comfortable) to +0.047 (barely)

  ──────────────────────────────────────────────────────────

  H3: "Hybrid model will achieve highest overall TPR and
       provide defence-in-depth through complementary coverage"
  
  RESULT: TPR(C) = 100% across all scenarios
          When A degrades to 33%, B compensates
          Both A and B fire on S3 via independent signals
  VERDICT: ✓ CONFIRMED
    Hybrid maintains 100% where A alone drops to 33%
    Complementary: A detects S3 via frequency, B via entropy
""")


# ══════════════════════════════════════════════════════════════
# SECTION 8: KEY RESEARCH FINDINGS
# ══════════════════════════════════════════════════════════════

print(f"{'='*75}")
print(f"SECTION 8 — KEY RESEARCH FINDINGS")
print(f"{'='*75}")

print(f"""
  FINDING 1: Signature-Based Detection Degrades Predictably
    Approach A degrades from 100% to 33% as evasion increases.
    Each rule fails for a specific, explainable reason:
    - Length rules fail when adversary mimics baseline length
    - Pattern rules fail against unknown (custom) tools
    - Frequency rules survive longest due to evasion trade-offs

  FINDING 2: The Evasion Trade-Off
    S3 mimicry reduced subdomain length (21→6 chars) to defeat
    Rule 1, but this required splitting data into more chunks,
    increasing query frequency (6.8→21.2 q/min) and keeping
    Rule 2 active. Reducing one detectable feature amplified
    another. The attacker cannot optimise both simultaneously
    without reducing C2 channel throughput.

  FINDING 3: Scorer Margin as Detection Boundary
    Approach B detects all scenarios but the margin shrinks 87%.
    S3 is only 0.047 above the threshold — and only 0.049
    above the highest-scoring normal domain (cloudfront.net).
    An adversary who combines length mimicry WITH frequency
    control could reduce the score below θ, defeating Approach B.
    This defines the detection boundary for lightweight methods.

  FINDING 4: Hybrid Resilience Through Complementary Weakness
    Approach C survives because A and B fail on DIFFERENT features.
    A catches S3 via frequency (the mimicry trade-off).
    B catches S3 via entropy and unique ratio.
    These are independent signals — defeating both requires
    a fundamentally different evasion strategy.

  FINDING 5: Reproducibility Confirms Reliability
    Detection outcomes (TPR values) are identical across
    repeated runs despite randomised timing. Deterministic
    encoding features (entropy, length) vary <2% between runs,
    confirming that results are not artifacts of random timing.
""")


# ══════════════════════════════════════════════════════════════
# SECTION 9: DETECTION BOUNDARY SUMMARY
# ══════════════════════════════════════════════════════════════

print(f"{'='*75}")
print(f"SECTION 9 — DETECTION BOUNDARY SUMMARY")
print(f"{'='*75}")

print(f"""
  ┌────────────────────┬──────────────────────────────────────────┐
  │ Detection Approach │ Failure Boundary                         │
  ├────────────────────┼──────────────────────────────────────────┤
  │ Approach A         │ First degrades at S2 (100% → 67%)       │
  │                    │ Near-failure at S3 (33% — 1 of 3 rules) │
  ├────────────────────┼──────────────────────────────────────────┤
  │ Approach B         │ Does not fail but margin shrinks 87%    │
  │                    │ Boundary: score 0.387 vs threshold 0.34 │
  │                    │ Predicted failure: adversary controls    │
  │                    │ both length AND frequency simultaneously │
  ├────────────────────┼──────────────────────────────────────────┤
  │ Approach C         │ Most resilient — no failure observed     │
  │                    │ Survives because A and B have            │
  │                    │ complementary failure modes              │
  └────────────────────┴──────────────────────────────────────────┘
  
  FUTURE WORK:
    An S4 scenario combining mimicry with frequency control
    (buffering chunks, reducing query rate) could potentially
    defeat all three approaches. This is the primary direction
    for future ML-based detection research.
""")


# ══════════════════════════════════════════════════════════════
# SAVE FINAL RESULTS CSV
# ══════════════════════════════════════════════════════════════

matrix_data = [
    {
        'Scenario': 'S1 (Low Evasion)',
        'A_TPR': 1.000, 'A_Rules_Fired': '3/3', 'A_Alerts': 1471,
        'B_TPR': 1.000, 'B_Score': 0.6968, 'B_Margin': 0.3568,
        'C_TPR': 1.000, 'C_Source': 'Both A and B',
    },
    {
        'Scenario': 'S2 (Medium Evasion)',
        'A_TPR': 0.667, 'A_Rules_Fired': '2/3', 'A_Alerts': 10,
        'B_TPR': 1.000, 'B_Score': 0.3914, 'B_Margin': 0.0514,
        'C_TPR': 1.000, 'C_Source': 'Both A and B',
    },
    {
        'Scenario': 'S3 (High Evasion)',
        'A_TPR': 0.333, 'A_Rules_Fired': '1/3', 'A_Alerts': 8,
        'B_TPR': 1.000, 'B_Score': 0.3870, 'B_Margin': 0.0470,
        'C_TPR': 1.000, 'C_Source': 'Both A and B',
    },
]

repro_data = [
    {
        'Scenario': 'S2 Run 2',
        'A_TPR': 0.667, 'A_Rules_Fired': '2/3', 'A_Alerts': 32,
        'B_TPR': 1.000, 'B_Score': 0.4181, 'B_Margin': 0.0781,
        'C_TPR': 1.000, 'C_Source': 'Both A and B',
    },
    {
        'Scenario': 'S3 Run 2',
        'A_TPR': 0.333, 'A_Rules_Fired': '1/3', 'A_Alerts': 10,
        'B_TPR': 1.000, 'B_Score': 0.4131, 'B_Margin': 0.0731,
        'C_TPR': 1.000, 'C_Source': 'Both A and B',
    },
]

# Save main matrix
df_matrix = pd.DataFrame(matrix_data)
matrix_path = os.path.join(RESULTS_DIR, 'final_results_matrix.csv')
df_matrix.to_csv(matrix_path, index=False)
print(f"\nMain matrix saved: {matrix_path}")

# Save reproducibility data
df_repro = pd.DataFrame(repro_data)
repro_path = os.path.join(RESULTS_DIR, 'reproducibility_results.csv')
df_repro.to_csv(repro_path, index=False)
print(f"Reproducibility saved: {repro_path}")

# Save combined
df_all = pd.DataFrame(matrix_data + repro_data)
all_path = os.path.join(RESULTS_DIR, 'all_results_combined.csv')
df_all.to_csv(all_path, index=False)
print(f"Combined saved: {all_path}")

print(f"\n{'='*75}")
print(f"PHASE 4 COMPLETE — All results compiled and saved")
print(f"{'='*75}")
