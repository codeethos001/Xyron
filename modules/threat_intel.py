import ipaddress
import os

THREAT_LIST_PATH = "threatintel/bad_ips.txt"

class ThreatIntel:
    def __init__(self):
        self.threat_entries = []
        self.load_list()

    def load_list(self):
        if not os.path.exists(THREAT_LIST_PATH):
            print("[ThreatIntel] No threat list found, creating empty file...")
            os.makedirs("threatintel", exist_ok=True)
            open(THREAT_LIST_PATH, "w").close()
            return

        with open(THREAT_LIST_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    if "/" in line:
                        self.threat_entries.append(ipaddress.ip_network(line, strict=False))
                    else:
                        self.threat_entries.append(ipaddress.ip_address(line))
                except:
                    pass

        print(f"[ThreatIntel] Loaded {len(self.threat_entries)} threat entries.")

    def check_ip(self, ip):
        """Return True if IP is malicious."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except:
            return False

        for entry in self.threat_entries:
            # If entry is a subnet
            if isinstance(entry, ipaddress.IPv4Network):
                if ip_obj in entry:
                    return True
            else:
                # Direct match
                if ip_obj == entry:
                    return True

        return False
