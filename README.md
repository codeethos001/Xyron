# Xyron (HIDS)

Xyron is a lightweight and extensible Host-Based Intrusion Detection System (HIDS) written in Python. It monitors system activities, network traffic, and file integrity to detect suspicious behavior, unauthorized access, and potential malware execution.

Designed for Linux environments, Xyron acts as a security web server for the host, analyzing behavior in real-time.

## Key Features

### 1. Core Monitoring Modules

   - Processes: Detects high CPU usage, suspicious binary paths (/tmp, /dev/shm), and known attack tools (ncat, nmap).
   - Network (Sniffer): Real-time packet analysis using Scapy. Detects SYN Scans, ICMP Floods, ARP Spoofing, and malicious payloads (SQLi, XSS).
   - File Integrity (FIM): Monitors critical system files (/etc/passwd, /etc/shadow) for unauthorized modifications using SHA-256 hashing.
   - Authentication: Watches system logs (auth.log) for brute-force attacks, Root logins, and Sudo abuse.
   - Cron Jobs: Detects persistence mechanisms via unauthorized scheduled tasks.
   - Users & Groups: Alerts on new user creation, privilege escalation (sudo group additions), or UID changes.

### 2. Advanced Detection

   - Signature Engine: Regex-based pattern matching for known exploit commands (e.g., Reverse Shells, Base64 decoding).
   - ML Anomaly Detector: A lightweight Machine Learning module (using Isolation Forest) that learns baseline system behavior and flags anomalies.
   - Threat Intelligence: Checks IPs against a local blacklist of known malicious actors.

### 3. Architecture

   - Central Alert Manager: Unified logging with console output and file persistence.
   - Multi-threaded: Network sniffing runs asynchronously to ensure non-blocking detection.
   - JSON Configuration: Fully configurable thresholds, paths, and intervals.

## Installation

### Prerequisites

   - Linux OS (Ubuntu/Debian/Arch/RHEL)
   - Python 3.8+
   - Root privileges (required for packet sniffing and system log access)

### Setup

#### Clone the Repository

```bash
git clone https://github.com/codeethos001/xyron.git
cd xyron
```

#### Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

Xyron must be run with sudo to access network interfaces and system logs. We pass the user's environment variables to keep the virtual environment active.

```bash
sudo -E env "PATH=$PATH" python3 xyron_main.py
```

## Configuration

### Modify config.json to tune the system:

- monitor_intervals: How often to scan (in seconds).
- thresholds: CPU/Memory limits for alerts.
- network: Whitelist IPs and scan thresholds.
- paths: Files to monitor for integrity.