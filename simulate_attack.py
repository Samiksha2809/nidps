from scapy.all import IP, TCP, send
import time

# Your machine’s IP from your output
target_ip = "127.0.0.1"  # Or use "127.0.0.1" for localhost

# Simulate Port Scanning (>6 ports in 15s)
def simulate_port_scan():
    print("Simulating port scan...")
    ports = [80, 81, 82, 83, 84, 85, 86, 87]  # 8 ports to trigger >6 rule
    for port in ports:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(packet, verbose=0)
        time.sleep(0.1)  # Small delay to stay within 15s

# Simulate Sequential Port Scanning
def simulate_sequential_scan():
    print("Simulating sequential port scan...")
    ports = [100, 101, 102, 103, 104]  # 5 sequential ports
    for port in ports:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(packet, verbose=0)
        time.sleep(0.1)

# Simulate OS Fingerprinting (5+ unique flags)
def simulate_os_fingerprinting():
    print("Simulating OS fingerprinting...")
    flag_combos = ["S", "SA", "F", "PA", "FA"]  # 5 unique flag combinations
    for flags in flag_combos:
        packet = IP(dst=target_ip) / TCP(dport=80, flags=flags)
        send(packet, verbose=0)
        time.sleep(0.1)

if __name__ == "__main__":
    simulate_port_scan()
    time.sleep(5)  # Wait between tests
    simulate_sequential_scan()
    time.sleep(5)
    simulate_os_fingerprinting()