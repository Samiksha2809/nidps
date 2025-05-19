#!/usr/bin/env python3

from scapy.all import IP, TCP, send
import time
import random

SRC_IP = "127.0.0.1"
DST_IP = "127.0.0.1"

def send_normal_traffic():
    print("Simulating normal traffic...")
    packet = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=12345, dport=80, flags="PA")
    send(packet, verbose=0, iface="lo")
    time.sleep(1)
    packet = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=12345, dport=80, flags="A")
    send(packet, verbose=0, iface="lo")
    print("Normal traffic sent.")

def simulate_syn_flood():
    print("Simulating SYN flood...")
    for _ in range(60):  # Send 60 SYN packets to exceed 50
        packet = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=12345, dport=80, flags="S")
        send(packet, verbose=0, iface="lo")
        time.sleep(0.1)  # ~6 seconds total
    print("SYN flood sent.")

def simulate_port_scan():
    print("Simulating port scan...")
    ports = [22, 23, 85, 443, 8080, 3306, 21]  # 7 ports
    for port in ports:
        packet = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=12345, dport=port, flags="S")
        send(packet, verbose=0, iface="lo")
        time.sleep(1)
    print("Port scan sent.")

def simulate_os_fingerprinting():
    print("Simulating OS fingerprinting...")
    flag_combinations = ["S", "SA", "F", "PA", "RA"]
    for flags in flag_combinations:
        packet = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=12345, dport=80, flags=flags)
        send(packet, verbose=0, iface="lo")
        time.sleep(2)
    print("OS fingerprinting sent.")

if __name__ == "__main__":
    print("Starting test simulation...")
    #send_normal_traffic()
    time.sleep(5)
    #simulate_syn_flood()
    time.sleep(5)
    #simulate_port_scan()
    # time.sleep(5)
    #simulate_os_fingerprinting()
    print("Test simulation complete.")