import os
import json
import csv
from datetime import datetime, timedelta

# === CONFIG ===
LOG_DIR = "logs"
LOG_INTERVAL = timedelta(hours=2)

# === State ===
log_buffer = []
last_flush_time = datetime.now()

# Creat logs/directory if needed
os.makedirs(LOG_DIR, exist_ok=True)

def log_packet(packet_data: dict):
    """
    Adds a single packet's to the in-memory log buffer.
    If the buffer is older than 2 hours, flush it to the disk.
    """
    global last_flush_time
    
    if not isinstance(packet_data, dict):
        print("[!] Invalid packet format:", packet_data)
        return
    log_buffer.append(packet_data)
    if datetime.now() - last_flush_time >+ LOG_INTERVAL:
        flush_logs()

def flush_logs():
    """
    Writes buffered logs to both JSON and CSV files,
    clears the buffer, and updates last flush time
    """
    global log_buffer, last_flush_time

    if not log_buffer:
        print("[!] No logs to flush.")
        return                                          #nothing to flush
    
    # Filter out any invalid items (non-dicts or empty dicts)
    clean_logs = [entry for entry in log_buffer if isinstance(entry, dict) and entry]

    if not clean_logs:
        print("[!] Log buffer contained no valid packet entries.")
        return
    
    # Use fieldnames from the first clean entry
    fieldnames = list(clean_logs[0].keys())
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    json_path = os.path.join(LOG_DIR, f"packet_log_{timestamp}.json")
    csv_path = os.path.join(LOG_DIR, f"packet_log_{timestamp}.csv")

    #Save JSON
    with open(json_path, "w") as f:
        json.dump(log_buffer, f, indent=2)
    
    #Save CSV
    keys = log_buffer[0].keys() if log_buffer else None
    if keys:
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, filenames=keys)
            writer.writeheader()
            writer.writerows(log_buffer)
    
    else:
        print("[!] No valid data for CSV - skipping write.")

    #Clear Buffer and Update Timestamp
    
    print(f"[+] Flushed {len(clean_logs)} packets to logs.")
    log_buffer= []
    last_flush_time = datetime.now()