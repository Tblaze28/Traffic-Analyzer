from logger import log_packet, flush_logs

# Example packet callback
def handle_packet(pkt):
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "src": pkt[IP].src if IP in pkt else "",
        "dst": pkt[IP].dst if IP in pkt else "",
        "protcol": pkt.name
    }
    log_packet(log_data)