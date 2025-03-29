# Packet Capture

from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP

# Callback will be injected from other modules
def start_sniffing(packet_callback, iface=None, count=0, filter=None):
    """
    Start packet sniffing
    
    Args:
        packet_callback (function): Functino to process each packet
        iface (str, optional): Netowrk interface to sniff on.
        count (int, optional): Number of packets to capture (0 = infinite).
        filter (str, optional): BPF filter string (e.g., "tcp)
        """
    sniff(prn=packet_callback, iface=iface, count=count, filter=filter)