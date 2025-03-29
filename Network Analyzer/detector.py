# detector.py

from collections import defaultdict, deque
from datetime import datetime, timedelta

# === Internal State ===

# Track port scan attempts
port_activity = defaultdict(lambda: deque(maxlen=1000))             # src_ip -> (timestamp, dport)

# Track DNS flood attempts
dns_activity = defaultdict(lambda: deque(maxlen=500))               # src_ip -> timestamp

# Track SYN floods
syn_activity = defaultdict(lambda: deque(maxlen=1000))              # src_ip -> timestamp

# Track deneral packet rate
packet_activity = defaultdict(lambda: deque(maxlen=500))                  # src_ip -> timestamp

# === Threshold Configurations ===

TIME_WINDOW = timedelta(seconds=60)
PORT_SCAN_THRESHOLD = 20
DNS_FLOOD_THRESHOLD = 30
SYN_FLOOD_THRESHOLD = 100
PACKET_RATE_THRESHOLD = 150

BLACKLISTED_IPS = {""}                                          # BLACKLIST IP ADDRESSES


# === Main Analysis ===

def analyze_packet(packet_data: dict) -> list[str]:
    """
    Takes one parsed packet, returns a list of triggered alerts.
    """
    alerts = []
    now = datetime.now()

    src = packet_data.get("src", "")
    proto = packet_data.get("protocol", "")
    dport = packet_data.get("dport", None)
    flags = packet_data.get("flags", "")

    # === Rule 1: Blacklist ===
    if src in BLACKLISTED_IPS:
        alerts.append(f"🚫 Blocked IP {src} sent a packet")

    # === Rule 2: Port Scan Detection ===
    if proto == "TCP" and dport:
        port_activity[src].append((now, dport))
        recent_ports = {p for t, p in port_activity[src] if now - t <= TIME_WINDOW}
        if len(recent_ports) >= PORT_SCAN_THRESHOLD:
            alerts.append(f"⚠️ Port scan from {src}: {len(recent_ports)} ports hit in 60s")

    # === Rule 3: DNS Flood ===
    if proto == "DNS":
        dns_activity[src].append(now)
        recent_dns = [t for t in dns_activity[src] if now - t <= TIME_WINDOW]
        if len(recent_dns) >= DNS_FLOOD_THRESHOLD:
            alerts.append(f"⚠️ DNS flood from {src}: {len(recent_dns)} requests in 60s")
    
    # === Rule 4: SYN Flood ===
    if proto == "TCP" and flags == "S":     #SYN-only packets
        syn_activity[src].append(now)
        recent_syns = [t for t in syn_activity[src] if now - t <= TIME_WINDOW]
        if len(recent_syns) >= PACKET_RATE_THRESHOLD:
            alerts.append(f"⚠️ SYN flood from {src}: {len(recent_syns)} SYNs in 60s")

    # === Rule 5: General Packet Burst ===
    packet_activity[src].append(now)
    recent_packets = [t for t in packet_activity[src] if now - t <= TIME_WINDOW]
    if len(recent_packets) >= PACKET_RATE_THRESHOLD:
        alerts.append(f"⚠️ High packet rate from {src}: {len(recent_packets)} in 60s")

    return alerts