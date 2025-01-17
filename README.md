# Monitor-Wi-Fi-Usage-with-ARP-and-Traffic-Counting
ython with ARP monitoring. This script tracks devices connected to the Wi-Fi network, calculates their data usage based on transmitted packets, and blocks devices exceeding a usage limit.
from scapy.all import ARP, sniff
import subprocess
import time
import threading

# Configuration
USAGE_LIMIT_MB = 500  # Limit in MB
CHECK_INTERVAL = 60  # Check interval in seconds
devices = {
    "192.168.1.101": {"name": "Student1", "usage": 0, "blocked": False},
    "192.168.1.102": {"name": "Student2", "usage": 0, "blocked": False}
}

# Function to block a device
def block_ip(ip_address):
    if not devices[ip_address]["blocked"]:
        try:
            subprocess.run(["iptables", "-A", "OUTPUT", "-s", ip_address, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            devices[ip_address]["blocked"] = True
            print(f"Blocked IP: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip_address}: {e}")

# Function to unblock a device
def unblock_ip(ip_address):
    if devices[ip_address]["blocked"]:
        try:
            subprocess.run(["iptables", "-D", "OUTPUT", "-s", ip_address, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            devices[ip_address]["blocked"] = False
            devices[ip_address]["usage"] = 0
            print(f"Unblocked IP: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP {ip_address}: {e}")

# Packet handler to track usage
def packet_handler(packet):
    if packet.haslayer(ARP):
        src_ip = packet.psrc
        if src_ip in devices:
            packet_size = len(packet)
            devices[src_ip]["usage"] += packet_size
            print(f"IP: {src_ip}, Usage: {devices[src_ip]['usage'] / (1024 * 1024):.2f} MB")

# Function to enforce limits
def enforce_limits():
    while True:
        time.sleep(CHECK_INTERVAL)
        for ip, data in devices.items():
            usage_mb = data["usage"] / (1024 * 1024)  # Convert bytes to MB
            if usage_mb > USAGE_LIMIT_MB and not data["blocked"]:
                block_ip(ip)

# Main function
def main():
    print("Starting ARP monitoring...")
    sniff(filter="arp", prn=packet_handler, store=0)

# Start the ARP monitoring and limit enforcement in parallel
if __name__ == "__main__":
    monitor_thread = threading.Thread(target=main, daemon=True)
    monitor_thread.start()

    enforce_limits()
