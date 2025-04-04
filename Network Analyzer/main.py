# Entry point
from scapy.all import sniff, IP, TCP, UDP, DNS
from detector import analyze_packet
from datetime import datetime
from logger import log_packet, flush_logs
from visualizer import update_stats, display_summary
from sniffer import start_sniffing
from visualizer import plot_protocol_distribution, display_summary, plot_top_source_ips
import atexit
atexit.register(display_summary)

# Example packet callback
def handle_packet(pkt):
    try:
            # Continue only if IP is present
        if IP not in pkt:
            return
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # === Packet log dictionary ===
        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "src": pkt[IP].src if IP in pkt else "",
            "dst": pkt[IP].dst if IP in pkt else "",
            "protcol": "OTHER", 
            "dport": pkt.dport if TCP in pkt or UDP in pkt else "None",
            "flags": ""
        }

        # TCP
        if TCP in pkt:
            packet_data["protocol"] = "TCP"
            packet_data["dport"] = pkt[TCP].dport
            if hasattr(pkt[TCP], "flags"):
                packet_data["flags"] = str(pkt[TCP].flags)

        # UDP / DNS
        elif UDP in pkt:
            packet_data["protocol"] = "UDP"
            packet_data["dport"] = pkt[UDP].dport
            if DNS in pkt:
                packet_data["protocol"] = "DNS"

        # Send to modules
        log_packet(packet_data)
        print(f"[DEBUG] Packet from {packet_data['src']} ({packet_data['protocol']})")
        update_stats(packet_data)

        alerts = analyze_packet(packet_data)
        for alert in alerts:
            print(alert)

    except Exception as e:
        print(f"[!] Error handling packet {e}")
        
        # === Send to modules ===
        alerts = analyze_packet(packet_data)
        for alert in alerts:
            print(alert)

        ## Log packet data
        log_packet(packet_data)
        update_stats(packet_data)
        flush_logs()
        
        print("Packet flags:", packet_data["flags"])
        print("Packet summary:", pkt.summary())
        print("Has IP?", IP in pkt)
  

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