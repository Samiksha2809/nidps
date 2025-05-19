#!/usr/bin/env python3

import os
import sys
import time
import threading
import subprocess
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import csv
import ipaddress

# Global variables
IDS_RUNNING = False
BLOCKED_IPS_FILE = "blocked_ips.txt"
LOG_FILE = "ids.log"
TRAFFIC_LOG = []
TRAFFIC_STATS = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
SYN_COUNTS = {}
LAST_SYN_TIME = {}

# Helper function for timestamp
def get_timestamp():
    return datetime.now().strftime("%d-%m-%y %H::%M::S")

# Log intrusion to file
def log_intrusion(intrusion_type, attacker_ip, target_ip, details, time_span):
    entry = f"{get_timestamp()} — {intrusion_type} — Attacker: {attacker_ip} — Target: {target_ip} — {details} — {time_span}s\n"
    with open(LOG_FILE, "a") as f:
        f.write(entry)
    print(f"Intrusion logged: {entry.strip()}")

# IP validation
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Load blocked IPs from file
def load_blocked_ips():
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r") as f:
                return set(line.strip() for line in f if line.strip())
        return set()
    except (IOError, PermissionError) as e:
        print(f"Error reading blocked IPs file: {e}")
        return set()

# Save blocked IPs to file
def save_blocked_ips(blocked_ips):
    try:
        with open(BLOCKED_IPS_FILE, "w") as f:
            for ip in blocked_ips:
                f.write(f"{ip}\n")
    except (IOError, PermissionError) as e:
        print(f"Error writing to blocked IPs file: {e}")

# Block IP (cross-platform)
def block_ip(ip, reason="Blocked due to intrusion"):
    if not is_valid_ip(ip):
        print(f"Invalid IP address: {ip}")
        return
    blocked_ips = load_blocked_ips()
    if ip not in blocked_ips:
        try:
            if sys.platform == "linux":
                subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True)
            elif sys.platform == "win32":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                f"name=Block_{ip}", "dir=in", "action=block",
                                f"remoteip={ip}"], check=True)
            else:
                print(f"Blocking IPs not supported on {sys.platform}")
                return
            blocked_ips.add(ip)
            save_blocked_ips(blocked_ips)
            print(f"{reason}: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip}: {e}")

# Unblock IP (cross-platform)
def unblock_ip(ip):
    if not is_valid_ip(ip):
        print(f"Invalid IP address: {ip}")
        return
    blocked_ips = load_blocked_ips()
    if ip in blocked_ips:
        try:
            if sys.platform == "linux":
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif sys.platform == "win32":
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                f"name=Block_{ip}"], check=True)
            blocked_ips.remove(ip)
            save_blocked_ips(blocked_ips)
            print(f"Unblocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to unblock IP {ip}: {e}")

# Clear block list
def clear_block_list():
    blocked_ips = load_blocked_ips()
    for ip in blocked_ips.copy():
        unblock_ip(ip)
    print("Block list cleared.")

# Packet analysis class
class IntrusionDetector:
    def __init__(self):
        self.traffic_data = defaultdict(lambda: {"ports": set(), "flags": set(), "timestamps": []})

    def analyze_packet(self, packet):
        protocol = "Other"
        if IP in packet:
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            TRAFFIC_STATS[protocol] += 1

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            direction = "Incoming" if dst_ip == "127.0.0.1" else "Outgoing"
            entry = f"Time: {get_timestamp()}, Src: {src_ip}:{packet[TCP].sport if TCP in packet else '-'}, Dst: {dst_ip}:{packet[TCP].dport if TCP in packet else '-'}, Protocol: {protocol}, Direction: {direction}"
            TRAFFIC_LOG.append(entry)

            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = packet[TCP].sprintf("%TCP.flags%")
                timestamp = time.time()

                # Update traffic data
                self.traffic_data[src_ip]["ports"].add(dst_port)
                self.traffic_data[src_ip]["flags"].add(flags)
                self.traffic_data[src_ip]["timestamps"].append(timestamp)

                # Clean old timestamps
                cutoff = timestamp - 20
                self.traffic_data[src_ip]["timestamps"] = [t for t in self.traffic_data[src_ip]["timestamps"] if t > cutoff]

                # Port Scanning Detection
                if len(self.traffic_data[src_ip]["timestamps"]) > 1:
                    time_span = timestamp - self.traffic_data[src_ip]["timestamps"][0]
                    ports = self.traffic_data[src_ip]["ports"]
                    ports_list = sorted(ports)
                    sequential = any(ports_list[i+1] - ports_list[i] == 1 for i in range(len(ports_list)-1))

                    if time_span <= 15:
                        if len(ports) > 6:
                            intrusion_type = "Sequential Port Scanning" if sequential else "Port Scanning"
                            ports_str = ", ".join(map(str, ports))
                            log_intrusion(intrusion_type, src_ip, dst_ip, ports_str, round(time_span, 2))
                            block_ip(src_ip, "Blocked attacker IP due to port scanning")
                            block_ip(dst_ip, "Blocked target IP due to port scanning")
                            self.traffic_data[src_ip]["ports"].clear()

                # OS Fingerprinting Detection
                if len(self.traffic_data[src_ip]["timestamps"]) > 1 and time_span <= 20:
                    if len(self.traffic_data[src_ip]["flags"]) >= 5:
                        flags_str = ", ".join(self.traffic_data[src_ip]["flags"])
                        log_intrusion("OS Fingerprinting", src_ip, dst_ip, flags_str, round(time_span, 2))
                        block_ip(src_ip, "Blocked attacker IP due to OS fingerprinting")
                        block_ip(dst_ip, "Blocked target IP due to OS fingerprinting")
                        self.traffic_data[src_ip]["flags"].clear()

                # SYN Flood Detection
                if packet[TCP].flags == "S":
                    SYN_COUNTS[src_ip] = SYN_COUNTS.get(src_ip, 0) + 1
                    LAST_SYN_TIME[src_ip] = timestamp
                    if SYN_COUNTS[src_ip] > 50:
                        log_intrusion("SYN Flood", src_ip, dst_ip, f"{SYN_COUNTS[src_ip]} SYN packets", 1)
                        block_ip(src_ip, "Blocked attacker IP due to SYN flood")
                        block_ip(dst_ip, "Blocked target IP due to SYN flood")
                        SYN_COUNTS[src_ip] = 0

                # Cleanup SYN counts
                for ip in list(SYN_COUNTS.keys()):
                    if timestamp - LAST_SYN_TIME.get(ip, 0) > 60:
                        SYN_COUNTS.pop(ip, None)

# Start sniffing (unchanged)
def start_sniffing():
    global IDS_RUNNING
    if not IDS_RUNNING:
        IDS_RUNNING = True
        detector = IntrusionDetector()
        print("IDS started. Sniffing network traffic...")
        def sniff_traffic():
            while IDS_RUNNING:
                try:
                    sniff(iface="lo", filter="tcp", prn=detector.analyze_packet, store=0, timeout=10)
                except Exception as e:
                    if IDS_RUNNING:
                        print(f"Sniffing error: {e}, restarting in 1s...")
                        time.sleep(1)
        threading.Thread(target=sniff_traffic, daemon=True).start()
    else:
        print("IDS is already running.")

# Stop IDS (unchanged)
def stop_ids():
    global IDS_RUNNING
    if IDS_RUNNING:
        IDS_RUNNING = False
        print("IDS stopped.")
    else:
        print("IDS is not running.")

# View live traffic (unchanged)
def view_traffic():
    print("\nLive Traffic (last 10 entries):")
    for entry in TRAFFIC_LOG[-10:]:
        print(entry)

# View logs (unchanged)
def view_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            print("\nIntrusion Logs:")
            print(f.read())
    else:
        print("No logs available.")

# Display blocked IPs (unchanged)
def display_blocked_ips():
    blocked_ips = load_blocked_ips()
    print("\nBlocked IPs:", blocked_ips if blocked_ips else "None")

# Generate detailed report (unchanged)
def generate_report():
    blocked_ips = load_blocked_ips()
    stats = {
        "total_intrusions": sum(1 for _ in open(LOG_FILE) if "—" in _ and "Configuration" not in _) if os.path.exists(LOG_FILE) else 0,
        "blocked_ips": len(blocked_ips),
        "port_scans": sum(1 for line in open(LOG_FILE) if "Port Scanning" in line and "Configuration" not in line) if os.path.exists(LOG_FILE) else 0,
        "os_fingerprints": sum(1 for line in open(LOG_FILE) if "OS Fingerprinting" in line and "Configuration" not in line) if os.path.exists(LOG_FILE) else 0,
        "syn_floods": sum(1 for line in open(LOG_FILE) if "SYN Flood" in line and "Configuration" not in line) if os.path.exists(LOG_FILE) else 0,
        "traffic_stats": TRAFFIC_STATS
    }
    print("\n=== Security Report ===")
    print(f"Total Intrusions Detected: {stats['total_intrusions']}")
    print(f"Currently Blocked IPs: {stats['blocked_ips']}")
    print(f"Port Scan Attempts: {stats['port_scans']}")
    print(f"OS Fingerprinting Attempts: {stats['os_fingerprints']}")
    print(f"SYN Flood Attacks: {stats['syn_floods']}")
    print(f"Traffic Statistics: {stats['traffic_stats']}")
    if os.path.exists(LOG_FILE):
        print("\nTop 5 Recent Intrusions:")
        with open(LOG_FILE, 'r') as f:
            intrusions = [line.strip() for line in f.readlines() if "—" in line and "Configuration" not in line]
            for line in intrusions[-5:]:
                print(line)

# Export logs to CSV (unchanged)
def export_logs_to_csv(export_file="exported_intrusion_logs.csv"):
    if not os.path.exists(LOG_FILE):
        print("No logs available to export.")
        return
    try:
        with open(LOG_FILE, "r") as infile, open(export_file, "w", newline="") as outfile:
            csv_writer = csv.writer(outfile)
            csv_writer.writerow(["Timestamp", "Intrusion Type", "Attacker IP", "Target IP", "Details", "Duration (s)"])
            for line in infile:
                if "—" in line and "Configuration" not in line:
                    parts = [part.strip() for part in line.strip().split("—")]
                    if len(parts) == 6:  # Updated to 6 due to added Target IP
                        csv_writer.writerow(parts)
        print(f"Logs successfully exported to {export_file}")
    except Exception as e:
        print(f"Failed to export logs: {e}")

# CLI Interface (unchanged except for main block)
def cli_interface():
    while True:
        print("\n=== NIDPS CLI ===")
        print("1. Start IDS")
        print("2. Stop IDS")
        print("3. View Live Traffic")
        print("4. View Intrusion Logs")
        print("5. Display Blocked IPs")
        print("6. Clear Block List")
        print("7. Unblock an IP")
        print("8. Generate Report")
        print("9. Export logs to csv")
        print("10. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            start_sniffing()
        elif choice == "2":
            stop_ids()
        elif choice == "3":
            view_traffic()
        elif choice == "4":
            view_logs()
        elif choice == "5":
            display_blocked_ips()
        elif choice == "6":
            clear_block_list()
        elif choice == "7":
            ip = input("Enter IP to unblock: ")
            unblock_ip(ip)
        elif choice == "8":
            generate_report()
        elif choice == "9":
            export_logs_to_csv()
        elif choice == "10":
            stop_ids()
            print("Exiting NIDPS.")
            sys.exit(0)
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    if sys.platform == "linux" and os.geteuid() != 0:
        print("This script requires root privileges for iptables on Linux. Run with sudo.")
        sys.exit(1)
    cli_interface()