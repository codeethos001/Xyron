from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
import time
from modules.threat_intel import ThreatIntel

class NetworkMonitor:
    def __init__(self, config, alert_manager):
        self.alert_manager = alert_manager
        self.threat_intel = ThreatIntel(config)
        
        # grab config stuff
        self.whitelist = set(config.get("network", {}).get("whitelist", ["127.0.0.1", "0.0.0.0"]))
        self.cooldown_time = config.get("network", {}).get("alert_cooldown", 60)
        self.syn_threshold = config.get("network", {}).get("syn_threshold", 15)
        
        # tracking vars
        self.traffic_stats = {} 
        self.alert_history = {}
        
        # keep track of mac addresses to spot spoofing
        self.arp_table = {} 
        
        self.last_cleanup = time.time()

    def _should_alert(self, ip, alert_type):
        """
        check if we need to yell or if we just yelled recently.
        returns True if we should alert.
        """
        key = (ip, alert_type)
        now = time.time()
        last_alert = self.alert_history.get(key, 0)
        
        if now - last_alert < self.cooldown_time:
            return False
            
        self.alert_history[key] = now
        return True

    def _cleanup(self):
        # clean up stats every 10s so we don't hoard memory
        now = time.time()
        if now - self.last_cleanup >= 10:
            self.traffic_stats = {}
            self.last_cleanup = now

    def packet_handler(self, pkt):
        self._cleanup()
        
        # --- ARP Spoofing Check (Local Network Attacks) ---
        if pkt.haslayer(ARP) and pkt[ARP].op == 2: # is-at reply
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            
            if src_ip in self.arp_table:
                # if the mac changed for the same IP, someone is likely messing around
                if self.arp_table[src_ip] != src_mac:
                    if self._should_alert(src_ip, "ARP_SPOOF"):
                        self.alert_manager.log_alert("NET", "CRITICAL", f"ARP Spoofing! IP {src_ip} mac changed from {self.arp_table[src_ip]} to {src_mac}")
            
            # update the table
            self.arp_table[src_ip] = src_mac

        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        
        # --- Noise Filtering ---
        # ignore local stuff or broadcast noise
        if src in self.whitelist or dst in self.whitelist: return
        if dst == "255.255.255.255" or dst.startswith("224.") or dst.startswith("239."): return

        # --- Threat Intel ---
        if self.threat_intel.check_ip(src):
            if self._should_alert(src, "MALICIOUS_IP"):
                self.alert_manager.log_alert("NET", "CRITICAL", f"Traffic from known bad IP: {src}")

        # init stats for new guys
        if src not in self.traffic_stats:
            self.traffic_stats[src] = {"syn_ports": set(), "icmp": 0}

        # --- TCP Analysis ---
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            dport = pkt[TCP].dport

            # Payload Inspection (Web Attack Signatures)
            # looking for obvious stuff like shell injection or SQLi in the packet text
            if pkt.haslayer(Raw):
                try:
                    payload = str(pkt[Raw].load).lower()
                    # simplistic keywords but effective for basic scripts
                    bad_keywords = ["union select", "/etc/passwd", "eval(", "<script>", "cmd.exe", "bash -i"]
                    for bad in bad_keywords:
                        if bad in payload:
                            if self._should_alert(src, "PAYLOAD_ATTACK"):
                                self.alert_manager.log_alert("NET", "CRITICAL", f"Payload Attack from {src}: found '{bad}'")
                except:
                    pass # ignore binary data

            # SYN Scan Logic
            # if they are hitting too many unique ports, they are mapping us
            if flags == "S":
                self.traffic_stats[src]["syn_ports"].add(dport)
                unique_ports = len(self.traffic_stats[src]["syn_ports"])
                
                if unique_ports >= self.syn_threshold:
                    if self._should_alert(src, "SYN_SCAN"):
                        self.alert_manager.log_alert("NET", "HIGH", f"SYN Scan from {src} (hit {unique_ports} ports)")

            # Weird Flags (Null, Xmas)
            # modern os don't usually send these, so its prob a scanner
            if flags == 0:
                if self._should_alert(src, "NULL_SCAN"):
                    self.alert_manager.log_alert("NET", "MEDIUM", f"NULL Scan from {src}")
            
            if flags == 0x29: # FPU (XMAS)
                if self._should_alert(src, "XMAS_SCAN"):
                    self.alert_manager.log_alert("NET", "MEDIUM", f"XMAS Scan from {src}")

        # --- ICMP Analysis ---
        if pkt.haslayer(ICMP):
            # only care about ping requests (type 8)
            if pkt[ICMP].type == 8:
                self.traffic_stats[src]["icmp"] += 1
                if self.traffic_stats[src]["icmp"] >= 30:
                    if self._should_alert(src, "ICMP_FLOOD"):
                        self.alert_manager.log_alert("NET", "MEDIUM", f"ICMP Flood incoming from {src}")

    def start(self):
        # store=False is key so we don't eat all the ram
        sniff(prn=self.packet_handler, store=False)