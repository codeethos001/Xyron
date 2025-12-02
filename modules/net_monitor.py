from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
import time
from modules.threat_intel import ThreatIntel

class NetworkMonitor:
    def __init__(self, config, alert_manager):
        self.alert_manager = alert_manager
        self.threat_intel = ThreatIntel(config)
        
        # Configuration
        self.whitelist = set(config.get("network", {}).get("whitelist", ["127.0.0.1", "0.0.0.0"]))
        self.cooldown_time = config.get("network", {}).get("alert_cooldown", 60)
        self.syn_threshold = config.get("network", {}).get("syn_threshold", 15)
        
        # State Tracking
        self.traffic_stats = {} 
        self.alert_history = {} 
        self.arp_table = {} 
        
        # Virtual Machine OUIs (VirtualBox, VMware, KVM)
        self.vm_ouis = ["08:00:27", "00:05:69", "00:0c:29", "00:50:56", "52:54:00"]
        
        self.last_cleanup = time.time()

    def _should_alert(self, ip, alert_type):
        key = (ip, alert_type)
        now = time.time()
        last_alert = self.alert_history.get(key, 0)
        
        # Determine cooldown based on alert type
        cooldown = self.cooldown_time
        
        # FIX: Increase cooldown for VM Flaps to 1 hour (3600s) to stop log spam
        if alert_type == "VM_BRIDGE_FLAP":
            cooldown = 3600
        
        if now - last_alert < cooldown:
            return False
            
        self.alert_history[key] = now
        return True

    def _cleanup(self):
        now = time.time()
        if now - self.last_cleanup >= 10:
            self.traffic_stats = {}
            # Cleanup alert history to prevent memory leak
            # We use a larger window (7200s) to ensure the 1-hour cooldown isn't deleted early
            keys_to_del = [k for k, v in self.alert_history.items() if now - v > 7200]
            for k in keys_to_del:
                del self.alert_history[k]
            self.last_cleanup = now

    def packet_handler(self, pkt):
        self._cleanup()
        
        # --- ARP Spoofing Check ---
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            
            if src_ip in self.arp_table:
                old_mac = self.arp_table[src_ip]
                
                # If MAC changed
                if old_mac != src_mac:
                    # Check if this involves a VM (False Positive Check)
                    is_vm_traffic = any(src_mac.startswith(oui) for oui in self.vm_ouis) or \
                                    any(old_mac.startswith(oui) for oui in self.vm_ouis)
                    
                    if is_vm_traffic:
                        # Log as LOW severity bridging noise, or ignore completely
                        if self._should_alert(src_ip, "VM_BRIDGE_FLAP"):
                            self.alert_manager.log_alert("NET", "INFO", f"VM Network Bridging detected (MAC Flap): {src_ip} {old_mac} -> {src_mac}")
                    else:
                        # Real Spoofing
                        if self._should_alert(src_ip, "ARP_SPOOF"):
                            self.alert_manager.log_alert("NET", "CRITICAL", f"ARP Spoofing! IP {src_ip} mac changed from {old_mac} to {src_mac}")

            self.arp_table[src_ip] = src_mac

        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        
        if src in self.whitelist or dst in self.whitelist: return
        if dst == "255.255.255.255" or dst.startswith("224.") or dst.startswith("239."): return

        # --- Threat Intel ---
        if self.threat_intel.check_ip(src):
            if self._should_alert(src, "MALICIOUS_IP"):
                self.alert_manager.log_alert("NET", "CRITICAL", f"Traffic from known bad IP: {src}")

        if src not in self.traffic_stats:
            self.traffic_stats[src] = {"syn_ports": set(), "icmp": 0}

        # --- TCP Analysis ---
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            dport = pkt[TCP].dport

            # Payload Inspection
            if pkt.haslayer(Raw):
                try:
                    payload = str(pkt[Raw].load).lower()
                    bad_keywords = ["union select", "/etc/passwd", "eval(", "<script>", "cmd.exe", "bash -i"]
                    for bad in bad_keywords:
                        if bad in payload:
                            if self._should_alert(src, "PAYLOAD_ATTACK"):
                                self.alert_manager.log_alert("NET", "CRITICAL", f"Payload Attack from {src}: found '{bad}'")
                except:
                    pass 

            # SYN Scan
            if flags == "S":
                self.traffic_stats[src]["syn_ports"].add(dport)
                if len(self.traffic_stats[src]["syn_ports"]) >= self.syn_threshold:
                    if self._should_alert(src, "SYN_SCAN"):
                        self.alert_manager.log_alert("NET", "HIGH", f"SYN Scan from {src} (Targeted {len(self.traffic_stats[src]['syn_ports'])} ports)")

            # Null / Xmas
            if flags == 0:
                if self._should_alert(src, "NULL_SCAN"):
                    self.alert_manager.log_alert("NET", "MEDIUM", f"NULL Scan from {src}")
            if flags == 0x29:
                if self._should_alert(src, "XMAS_SCAN"):
                    self.alert_manager.log_alert("NET", "MEDIUM", f"XMAS Scan from {src}")

        # --- ICMP Analysis ---
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            self.traffic_stats[src]["icmp"] += 1
            if self.traffic_stats[src]["icmp"] >= 30:
                if self._should_alert(src, "ICMP_FLOOD"):
                    self.alert_manager.log_alert("NET", "MEDIUM", f"ICMP Flood from {src}")

    def start(self):
        sniff(prn=self.packet_handler, store=False)