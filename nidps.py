import datetime
import time
from scapy.all import sniff, TCP, IP

# Existing from Step 2
traffic_log = {}  # {src_ip: [(timestamp, dst_port, flags)]}

# New globals for this step
blocked_ips = set()  # To track blocked IPs (for Step 4)
log_file = "ids.log"

def packet_callback(packet):
    """Process each captured packet (same as Step 2)."""
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        timestamp = time.time()

        if src_ip not in traffic_log:
            traffic_log[src_ip] = []
        traffic_log[src_ip].append((timestamp, dst_port, str(flags)))

        print(f"Time: {time.ctime(timestamp)} | Src: {src_ip}:{packet[TCP].sport} | "
              f"Dst: {packet[IP].dst}:{dst_port} | Protocol: TCP | Flags: {flags}")

def log_intrusion(intrusion_type, attacker_ip, details, time_span):
    """Log detected intrusions to ids.log."""
    with open(log_file, "a") as f:
        entry = (f"{datetime.datetime.now().strftime('%d-%m-%y %H:%M:%S')} - "
                 f"{intrusion_type} - {attacker_ip} - {details} - {time_span}s")
        f.write(entry + "\n")
    print(f"Intrusion Detected: {entry}")

def detect_intrusions():
    """Analyze traffic_log for intrusions."""
    while True:
        current_time = time.time()
        for ip, packets in list(traffic_log.items()):
            # Clean old packets (>20s to cover both 15s and 20s windows)
            packets = [(ts, port, flags) for ts, port, flags in packets if current_time - ts <= 20]
            traffic_log[ip] = packets

            if len(packets) == 0:
                continue

            # 1. Port Scanning Detection (>6 ports in 15s)
            ports_15s = set(p[1] for p in packets if current_time - p[0] <= 15)
            if len(ports_15s) > 6:
                time_span = round(current_time - packets[0][0], 2)
                log_intrusion("Port Scanning", ip, f"Ports: {','.join(map(str, ports_15s))}", time_span)
                del traffic_log[ip]  # Clear after detection
                continue

            # 2. Sequential Port Scanning
            ports_list = sorted([p[1] for p in packets if current_time - p[0] <= 15])
            if len(ports_list) > 3:
                for i in range(len(ports_list) - 3):
                    if ports_list[i+1] == ports_list[i] + 1 and \
                       ports_list[i+2] == ports_list[i] + 2 and \
                       ports_list[i+3] == ports_list[i] + 3:
                        time_span = round(current_time - packets[0][0], 2)
                        log_intrusion("Sequential Port Scanning", ip, f"Ports: {','.join(map(str, ports_list[i:i+4]))}", time_span)
                        del traffic_log[ip]
                        break

            # 3. OS Fingerprinting Detection (5+ unique flags in 20s)
            flags_20s = set(p[2] for p in packets if current_time - p[0] <= 20)
            if len(packets) >= 5 and len(flags_20s) >= 5:
                time_span = round(current_time - packets[0][0], 2)
                log_intrusion("OS Fingerprinting", ip, f"Flags: {','.join(flags_20s)}", time_span)
                del traffic_log[ip]

        time.sleep(1)  # Check every second

def start_sniffing():
    print("Starting packet sniffing...")
    sniff(iface="wlo1", filter="tcp", prn=packet_callback, store=0)

if __name__ == "__main__":
    # Run detection in a separate thread so sniffing continues
    import threading
    threading.Thread(target=detect_intrusions, daemon=True).start()
    start_sniffing()