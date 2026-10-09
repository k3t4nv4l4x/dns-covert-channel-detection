#!/bin/bash
# iptables.sh - Network forwarding and firewall rules for the DNS lab
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
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
Verify:
cat /proc/sys/net/ipv4/ip_forward
# Must show: 1

# Flush existing rules
iptables -F
iptables -t nat -F

# Allow all traffic on the internal lab network
iptables -A INPUT -s 192.168.100.0/24 -j ACCEPT
iptables -A FORWARD -s 192.168.100.0/24 -j ACCEPT

# Forward DNS traffic (port 53) through the gateway
# so Suricata can inspect it
iptables -A FORWARD -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -p tcp --dport 53 -j ACCEPT

# NAT for outbound traffic (if needed)
iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE

echo "Firewall rules applied. IP forwarding enabled."


# Block all forwarded traffic by default
 sudo iptables -P FORWARD DROP
 
 # Allow DNS queries to pass through (UDP port 53)
 sudo iptables -A FORWARD -p udp --dport 53 -j ACCEPT
 
 # Allow DNS replies to pass back
 sudo iptables -A FORWARD -p udp --sport 53 -j ACCEPT
 
 # Allow existing connections to continue
 sudo iptables -A FORWARD -m state \
   --state ESTABLISHED,RELATED -j ACCEPT
 
 # Allow DNS to reach the gateway itself
 sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT


Save iptables rules so they survive reboot:
 sudo apt install -y iptables-persi
