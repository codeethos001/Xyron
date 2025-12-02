import os
import json
import re

class AuthMonitor:
    def __init__(self, config):
        self.baseline_file = os.path.join(config["paths"]["baseline_dir"], "auth_baseline.json")
        
        # Detect OS log location
        if os.path.exists("/var/log/auth.log"):
            self.log_path = "/var/log/auth.log"
        elif os.path.exists("/var/log/secure"):
            self.log_path = "/var/log/secure"
        else:
            self.log_path = None
            
        self.baseline = self.load_baseline()

    def load_baseline(self):
        if not os.path.exists(self.baseline_file):
            return {"last_pos": 0}
        with open(self.baseline_file, "r") as f:
            return json.load(f)

    def save_baseline(self):
        with open(self.baseline_file, "w") as f:
            json.dump(self.baseline, f, indent=4)

    def scan(self):
        alerts = []
        events = []
        
        if not self.log_path:
            return [], []

        try:
            current_size = os.path.getsize(self.log_path)
            # Handle log rotation (file got smaller)
            if current_size < self.baseline["last_pos"]:
                self.baseline["last_pos"] = 0

            with open(self.log_path, "r") as f:
                f.seek(self.baseline["last_pos"])
                new_lines = f.readlines()
                self.baseline["last_pos"] = f.tell()

            for line in new_lines:
                # 1. Failed Passwords
                if "Failed password" in line:
                    user = self.extract_user(line)
                    ip = self.extract_ip(line)
                    alerts.append(f"Failed login for {user} from {ip}")
                    events.append(f"AUTH_FAIL user={user} ip={ip}")

                # 2. Sudo Abuse
                if "sudo:" in line and "authentication failure" in line:
                    user = self.extract_sudo_user(line)
                    alerts.append(f"Sudo Auth Failure for {user}")

                # 3. Root Login
                if "session opened for user root" in line:
                    alerts.append("Root session opened")
                    events.append("AUTH_ROOT_LOGIN")

            self.save_baseline()
        except Exception as e:
            # Handle permission errors gracefully
            pass

        return alerts, events

    def extract_ip(self, line):
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        return match.group(1) if match else "unknown"

    def extract_user(self, line):
        match = re.search(r"for (\w+)", line)
        return match.group(1) if match else "unknown"
        
    def extract_sudo_user(self, line):
        match = re.search(r"sudo: \s*(\w+)", line)
        return match.group(1) if match else "unknown"