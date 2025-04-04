import matplotlib
matplotlib.use("TkAgg")
from collections import Counter
from datetime import datetime
import matplotlib.pyplot as plt

# Global Stats
protocol_counter = Counter()
source_ip_counter = Counter()
packet_count = 0
start_time = datetime.now()

# Visualizer.py
def update_stats(packet_data: dict):
    """
    Updates in-memory stats for protocol and source IP counts.
    Call this for every packet.
    """
    global packet_count
    protocol = packet_data.get("protocol", "OTHER")
    src_ip = packet_data.get("src", "unkown")

    protocol_counter [protocol] += 1
    source_ip_counter[src_ip] += 1
    packet_count += 1

def display_summary(top_n=5):
    """
    Prints a terminal summary of traffic stats.
    """
    runtime = (datetime.now() - start_time).total_seconds()
    print("\n" + "="*40)
    print(f"📊 Traffic Summary (Runtime: {runtime:.1f}s)")
    print(f"Total Packets: {packet_count}")

    print("\nTop Protocols:")
    for proto, count in protocol_counter.most_common(top_n):
        print(f"  {proto:<10}: {count}")
    
    print("\nTop Source IPs:")
    for ip, count in source_ip_counter.most_common(top_n):
        print(f"  {ip:<15}: {count}")
    print("="*40 + "\n")

def plot_protocol_distribution():
    """
    Pie chart of protocol usage
    """
    labels = list(protocol_counter.keys())
    sizes = list(protocol_counter.values())

    if not sizes:
        print("No data to plot.")
        return

    plt.figures(figsize=(6, 6))
    plt.title("Protocol Distribution")
    plt.pie(sizes, labels=labels, autopct = "%1.1f%")
    plt.tight_layout()
    plt.show()

def plot_top_source_ips(top_n=5):
    """
    Bar chart of top source IPs.
    """
    top_ips = source_ip_counter.most_common(top_n)
    if not top_ips:
        print("No source IP data to plot.")
        return
    
    labels, counts = zip(*top_ips)

    plt.figure(figsize=(8, 5))
    plt.title("Top Source IPs")
    plt.bar(labels, counts)
    plt.ylabel("Packets")
    plt.xlabel("Source IP")
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.show()

# Summary
display_summary
plot_protocol_distribution
plot_top_source_ips(10)