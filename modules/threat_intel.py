import ipaddress
import os

class ThreatIntel:
    def __init__(self, config):
        self.threat_file = config["paths"]["threat_list"]
        self.threat_entries = []
        self.load_list()

    def load_list(self):
        if not os.path.exists(self.threat_file):
            # Create dummy file if missing
            os.makedirs(os.path.dirname(self.threat_file), exist_ok=True)
            with open(self.threat_file, "w") as f:
                f.write("# Add bad IPs here, one per line\n")
            return

        with open(self.threat_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                try:
                    if "/" in line:
                        self.threat_entries.append(ipaddress.ip_network(line, strict=False))
                    else:
                        self.threat_entries.append(ipaddress.ip_address(line))
                except:
                    pass

    def check_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            for entry in self.threat_entries:
                if isinstance(entry, ipaddress.IPv4Network):
                    if ip_obj in entry: return True
                elif ip_obj == entry:
                    return True
        except:
            pass
        return False