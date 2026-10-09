#!/bin/bash
# iptables.sh - Firewall rules for the DNS covert channel lab
# Run on VM2 (Gateway/IDS - 192.168.100.2)
#
# Lab network: VMnet1 Host-Only 192.168.100.0/24
#   VM1 (Attacker):    192.168.100.1
#   VM2 (Gateway/IDS): 192.168.100.2
#   VM3 (Victim):      192.168.100.3
#
# Author: Ketan Vala (23688958)

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Block all forwarded traffic by default
iptables -P FORWARD DROP

# Allow DNS queries to pass through (UDP port 53)
iptables -A FORWARD -p udp --dport 53 -j ACCEPT

# Allow DNS replies to pass back
iptables -A FORWARD -p udp --sport 53 -j ACCEPT

# Allow existing connections to continue
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS to reach the gateway itself
iptables -A INPUT -p udp --dport 53 -j ACCEPT

echo "Firewall rules applied."
echo "To persist across reboot:"
echo "  sudo apt install -y iptables-persistent"
echo "  sudo netfilter-persistent save"
