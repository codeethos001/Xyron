from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
from modules.threat_intel import threatintel

SUSPICIOUS_PORTS = {4444, 31337, 5555, 1337}

class NetworkMonitor:
    def __init__(self):
        self.counters = {}    # ip -> {syn:0, packets:0, icmp:0, dns:0}
        self.last_cleanup = time.time()

    def _init_ip(self, ip):
        if ip not in self.counters:
            self.counters[ip] = {
                "packets": 0,
                "syn": 0,
                "icmp": 0,
                "dns": 0,
            }

    def cleanup(self):
        """Reset counters every 10 seconds to avoid memory growth."""
        now = time.time()
        if now - self.last_cleanup >= 10:
            self.counters = {}
            self.last_cleanup = now

    def packet_handler(self, pkt):
        alerts = []

        # We only care about packets with an IP header
        if not pkt.haslayer(IP):
            return alerts

        src = pkt[IP].src
        self._init_ip(src)
        self.counters[src]["packets"] += 1

#       -----------------------------
#       Detect Large Packet
#       -----------------------------
        if len(pkt) > 1500:
            alerts.append(f"[NET] LARGE_PACKET {src} size={len(pkt)}")

#       -----------------------------
#       Detect TCP scans
#       -----------------------------
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags

            # SYN scan: many SYN packets without ACKs
            if flags == "S":
                self.counters[src]["syn"] += 1
                if self.counters[src]["syn"] >= 20:
                    alerts.append(f"[NET] Possible SYN Scan from {src}")

            # NULL Scan
            if flags == 0:
                alerts.append(f"[NET] NULL Scan packet from {src}")

            # FIN Scan
            if flags == "F":
                alerts.append(f"[NET] FIN Scan packet from {src}")

            # XMAS scan = FIN + PSH + URG flags
            if flags == "FPU":
                alerts.append(f"[NET] XMAS Scan packet from {src}")

            # Suspicious ports
            dport = pkt[TCP].dport
            if dport in SUSPICIOUS_PORTS:
                alerts.append(f"[NET] Suspicious port {dport} accessed by {src}")

#       -----------------------------
#       ICMP Flood
#       -----------------------------
        if pkt.haslayer(ICMP):
            icmp_type = pkt[ICMP].type
            if icmp_type == 8:  # echo request
                self.counters[src]["icmp"] += 1
                if self.counters[src]["icmp"] >= 30:
                    alerts.append(f"[NET] Possible ICMP Flood from {src}")

#       -----------------------------
#       DNS Flood
#       -----------------------------
        if pkt.haslayer(UDP) and pkt[UDP].dport == 53:
            self.counters[src]["dns"] += 1
            if self.counters[src]["dns"] >= 40:
                alerts.append(f"[NET] Possible DNS Flood from {src}")

        alerts = net_monitor.packet_handler(pkt)
        for alert in alerts:
            ip = extract_ip_from_alert(alert)
            if threatintel.check_ip(ip):
                print(f"[THREAT INTEL] {ip} is in blacklist! Known malicious source.")


        return alerts

    def start(self):
        """Start packet sniffing using Scapy."""
        print("[+] Network monitor is running...")
        sniff(prn=self.packet_handler, store=False)
