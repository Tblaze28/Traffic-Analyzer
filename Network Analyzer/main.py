# Entry point
from scapy.all import sniff, IP, TCP, UDP, DNS
from detector import analyze_packet
from datetime import datetime
from logger import log_packet, flush_logs
from visualizer import update_stats, display_summary
from sniffer import start_sniffing
from visualizer import plot_protocol_distribution, display_summary, plot_top_source_ips
import atexit
import sys
import signal
atexit.register(display_summary)

# Example packet callback
def handle_packet(pkt):
    try:
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        if not src_ip:
            print("[!] No src IP found, skipping packet.")
            return

        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "src": src_ip,
            "dst": pkt[IP].dst,
            "protocol": "OTHER",
            "dport": None,
            "flags": ""
        }

        if TCP in pkt:
            packet_data["protocol"] = "TCP"
            packet_data["dport"] = pkt[TCP].dport
            packet_data["flags"] = str(pkt[TCP].flags) if hasattr(pkt[TCP], "flags") else ""

        elif UDP in pkt:
            packet_data["protocol"] = "UDP"
            packet_data["dport"] = pkt[UDP].dport
            if DNS in pkt:
                packet_data["protocol"] = "DNS"

        print("[DEBUG] packet_data:", packet_data)

        log_packet(packet_data)
        update_stats(packet_data)

        alerts = analyze_packet(packet_data)
        for alert in alerts:
            print(alert)

    except Exception as e:
        print(f"[!] Error handling packet: {e}")
  

    except Exception as e:
        print(f"[!] Error handling packet {e}")

def graceful_shutdown(signal_received=None, frame=None):
    print("\n[+] Exiting and flushing logs...")
    flush_logs()
    display_summary()

    # 👇 Add these if missing
    print("[+] Plotting protocol distribution...")
    plot_protocol_distribution()

    print("[+] Plotting top source IPs...")
    plot_top_source_ips(10)

    sys.exit(0)

if __name__ == "__main__":
    print("[*] Starting network analyzer...")
    start_sniffing(packet_callback=handle_packet, iface="eth0", count=0)

    # Register shutdown handler
signal.signal(signal.SIGINT, graceful_shutdown)