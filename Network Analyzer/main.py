# Entry point
from detector import analyze_packet
from datetime import datetime
from logger import log_packet, flush_logs
from visualizer import update_stats, display_summary
import atexit
atexit.register(display_summary)

# Example packet callback
def handle_packet(pkt):
    # Packet log dictionary
    packet_data = {
        "timestamp": datetime.now().isoformat(),
        "src": pkt[IP].src if IP in pkt else "",
        "dst": pkt[IP].dst if IP in pkt else "",
        "protcol": pkt.name,
        "dport": pkt.dport if TCP in pkt or UDP in pkt else "None"
    }

    # Send to modules
    alerts = analyze_packet(packet_data)
    for alert in alerts:
        print(alert)

    ## Log packet data
    log_packet(packet_data)
    update_stats(packet_data)