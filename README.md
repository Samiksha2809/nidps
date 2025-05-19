# Network Intrusion Detection and Prevention System (NIDPS)


---

## Overview
This project implements a Network-based Intrusion Detection and Prevention System (NIDPS).The system monitors TCP network traffic, detects malicious activities using signature-based and anomaly-based techniques, logs intrusions, and dynamically blocks threats using `iptables`. A command-line interface (CLI) provides management and monitoring capabilities.

---

## Setup Instructions

### Prerequisites
- **Operating System**: Linux (tested on Ubuntu)
- **Python Version**: Python 3.6+
- **Dependencies**:
  - `scapy`: For packet capturing and analysis
  - `iptables`: For intrusion prevention (pre-installed on most Linux systems)

### Installation
1. Install Python 3 if not already installed:
   ```bash
   sudo apt update
   sudo apt install python3
   ```

2. Install Scapy:
   ```bash
   sudo apt install python3-scapy
   ```

3. Ensure iptables is available (typically pre-installed):
   ```bash
   sudo iptables -L
   ```
   If not installed, install it:
   ```bash
   sudo apt install iptables
   ```

### Permissions
The script requires root privileges to modify iptables rules and capture network traffic. Run it with sudo.

## How to Build and Run

### Build
No compilation is required as the implementation uses Python, an interpreted language.

### Run
1. Save the script as `nidps.py`.
2. Execute the program with root privileges:
   ```bash
   sudo python3 nidps.py
   ```
3. The CLI will launch, allowing you to interact with the NIDPS.

## Implementation Steps

### 1. Network Traffic Monitoring
- **Library**: Uses scapy to capture live TCP packets.
- **Details**: The sniff function filters TCP traffic and passes packets to the analyze_packet method. Captures timestamps, source/destination IPs, ports, and protocol (TCP). Traffic is stored in TRAFFIC_LOG for live viewing.

### 2. Intrusion Detection Module
- **Class**: IntrusionDetector
- **Port Scanning Detection (Anomaly-based)**:
  - Tracks IPs connecting to multiple ports within 15 seconds.
  - Flags if >6 unique ports are targeted, logs the event, and blocks the IP.
- **OS Fingerprinting Detection (Signature-based)**:
  - Detects IPs sending ≥5 unique TCP flag combinations (e.g., SYN, ACK, FIN) within 20 seconds.
  - Logs the flags and blocks the IP.

### 3. Intrusion Prevention Mechanism
- **Tool**: Uses iptables to dynamically block malicious IPs.
- **Functions**:
  - `block_ip`: Adds a rule to drop packets from the attacker's IP.
  - `unblock_ip`: Removes the rule for a specified IP.
  - `clear_block_list`: Unblocks all IPs.

### 4. Alert and Logging
- **Log File**: `ids.log`
- **Format**: Date(DD-MM-YY) Time(HH:MM:SS) - Intrusion Type - Attacker IP - Targeted Ports/Flags - Time Span
- **Details**: Logs are appended for each detected intrusion; viewable via the CLI.

### 5. Management Interface
- **CLI Options**:
  1. Start IDS: Begins packet sniffing in a separate thread.
  2. Stop IDS: Stops sniffing and joins the thread.
  3. View Live Traffic: Shows the last 10 traffic entries.
  4. View Intrusion Logs: Displays contents of ids.log.
  5. Display Blocked IPs: Lists IPs in BLOCKED_IPS.
  6. Clear Block List: Unblocks all IPs.
  7. Unblock an IP: Prompts for an IP to unblock.
  8. Generate Report: Generate a report showing the top 5 attacks
  9. Export logs to csv : Export logs as a csv file
  10. Exit : Exit

## Input and Output

### Inputs
- **CLI Commands**: Enter numbers 1-10 to select options.
- **Unblock IP**: Enter a specific IP address when prompted under option 7.

### Outputs
- **Live Traffic**: Displays timestamp, source/destination IPs, ports, and protocol for the last 10 packets.
- **Intrusion Logs**: Shows logged intrusions from ids.log in the specified format.
- **Blocked IPs**: Lists currently blocked IPs or "None" if empty.
- **Console Messages**: Confirms actions (e.g., "Blocked IP: 192.168.1.1", "IDS started").

### Sample Log Entry
```
07-04-25 14:30:45 - Port Scanning - 192.168.1.10 - 22, 80, 443, 445, 8080, 3389 - 12.34s
07-04-25 14:31:00 - OS Fingerprinting - 10.0.0.5 - S, SA, F, FA, RA - 18.56s
```

## Testing
- **Port Scanning**: Use nmap (e.g., `nmap -p 1-100 <target_ip>`) to simulate a port scan.
- **OS Fingerprinting**: Craft packets with tools like hping3 (e.g., `hping3 -S -A -F <target_ip>`).
- **Traffic**: Generate TCP traffic (e.g., HTTP requests, SSH attempts) to observe live monitoring.
- Ensure the system is tested on a network interface with traffic (default is all interfaces).

## Files Included
- `nidps.py`: Main Python script implementing the NIDPS.
- `ids.log`: Log file with detected intrusions (generated during execution).
- `README.md`: This documentation.
- `test.py` : This python script contains code for simulating normal traffic, syn flood, port   scanning and os Fingerprinting. It has both source and destinations ips as localhost. To simualte a particular kind of traffic, uncomment that function and comment the remaining ones.

## Notes
- Run the script with sudo to avoid permission errors.
- The system assumes a Linux environment with iptables. It won't work on Windows without modifications.
- Ensure no firewall rules conflict with iptables operations during testing.
