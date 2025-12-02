from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
from modules.threat_intel import ThreatIntel

SUSPICIOUS_PORTS = {4444, 31337, 5555, 1337, 6667}

class NetworkMonitor:
    def __init__(self, config, alert_manager):
        self.alert_manager = alert_manager
        self.threat_intel = ThreatIntel(config)
        self.counters = {}    # ip -> {syn:0, packets:0, icmp:0, dns:0}
        self.last_cleanup = time.time()

    def _init_ip(self, ip):
        if ip not in self.counters:
            self.counters[ip] = {"packets": 0, "syn": 0, "icmp": 0, "dns": 0}

    def cleanup(self):
        """Reset counters every 10 seconds."""
        now = time.time()
        if now - self.last_cleanup >= 10:
            self.counters = {}
            self.last_cleanup = now

    def packet_handler(self, pkt):
        self.cleanup()
        
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        
        # Threat Intel Check
        if self.threat_intel.check_ip(src):
            self.alert_manager.log_alert("NET", "CRITICAL", f"Inbound Traffic from Malicious IP: {src}")
        if self.threat_intel.check_ip(dst):
            self.alert_manager.log_alert("NET", "CRITICAL", f"Outbound Connection to Malicious IP: {dst}")

        self._init_ip(src)
        self.counters[src]["packets"] += 1

        # 1. Large Packet Detection
        if len(pkt) > 1500:
            self.alert_manager.log_alert("NET", "LOW", f"Large Packet from {src} size={len(pkt)}")

        # 2. TCP Analysis
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            dport = pkt[TCP].dport

            # SYN Scan Logic
            if flags == "S":
                self.counters[src]["syn"] += 1
                if self.counters[src]["syn"] >= 20:
                    self.alert_manager.log_alert("NET", "HIGH", f"Possible SYN Scan from {src}")
                    self.counters[src]["syn"] = 0 # Reset to avoid spam

            # Bad Flags
            if flags == 0:
                self.alert_manager.log_alert("NET", "MEDIUM", f"NULL Scan packet from {src}")
            if flags == 0x29: # FPU (XMAS)
                self.alert_manager.log_alert("NET", "MEDIUM", f"XMAS Scan packet from {src}")

            if dport in SUSPICIOUS_PORTS:
                self.alert_manager.log_alert("NET", "HIGH", f"Suspicious port {dport} accessed by {src}")

        # 3. ICMP Flood
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            self.counters[src]["icmp"] += 1
            if self.counters[src]["icmp"] >= 30:
                self.alert_manager.log_alert("NET", "MEDIUM", f"Possible ICMP Flood from {src}")
                self.counters[src]["icmp"] = 0

    def start(self):
        # Store=False prevents memory leaks from keeping packets in RAM
        sniff(prn=self.packet_handler, store=False) 