import os
import json
import re
from datetime import datetime, timedelta

AUTH_LOG = "/var/log/auth.log"   # for debian
ALT_AUTH_LOG = "/var/log/secure" # for arch/redhat/fedora

BASELINE_FILE = "baseline/auth_baseline.json"

class AuthMonitor:
    def __init__(self):
        self.log_path = AUTH_LOG if os.path.exists(AUTH_LOG) else ALT_AUTH_LOG
        self.baseline = self.load_baseline()

    def load_baseline(self):
        if not os.path.exists(BASELINE_FILE):
            return {"last_pos": 0, "known_ssh_ips": []}
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)

    def save_baseline(self):
        with open(BASELINE_FILE, "w") as f:
            json.dump(self.baseline, f, indent=4)

    def scan(self):
        alerts = []
        events = []

        if not os.path.exists(self.log_path):
            return ["[AUTH] Log file missing."], events

        with open(self.log_path, "r") as f:
            f.seek(self.baseline["last_pos"])
            new_lines = f.readlines()
            self.baseline["last_pos"] = f.tell()

        failed_count = {}
        ssh_ips = self.baseline.get("known_ssh_ips", [])

        for line in new_lines:
            
#           -------------------------------
#           Failed login (local + SSH)
#           -------------------------------
            if "Failed password" in line:
                ip = self.extract_ip(line)
                user = self.extract_user(line)
                key = f"{user}:{ip}"

                failed_count[key] = failed_count.get(key, 0) + 1

                alerts.append(f"[AUTH] Failed login for user={user} from {ip}")
                events.append(f"FAILED_LOGIN:{user}:{ip}")

#           -------------------------------
#           Successful login 
#           -------------------------------
            if "Accepted password" in line or "session opened for user" in line:
                ip = self.extract_ip(line)
                user = self.extract_user(line)

                alerts.append(f"[AUTH] Successful login for {user} from {ip}")
                events.append(f"LOGIN:{user}:{ip}")

                # detect first-time IP
                if ip and ip not in ssh_ips:
                    alerts.append(f"[AUTH] New SSH IP detected: {ip}")
                    ssh_ips.append(ip)

#           -------------------------------
#           Sudo success
#           -------------------------------
            if "sudo:" in line and "COMMAND=" in line:
                user = self.extract_sudo_user(line)
                alerts.append(f"[AUTH] SUDO command executed by {user}")
                events.append(f"SUDO_SUCCESS:{user}")

#           -------------------------------
#           Sudo failure
#           -------------------------------
            if "sudo:" in line and "authentication failure" in line:
                user = self.extract_sudo_user(line)
                alerts.append(f"[AUTH] SUDO authentication failure for {user}")
                events.append(f"SUDO_FAIL:{user}")

#           -------------------------------
#           su usage
#           -------------------------------
            if "su:" in line and "session opened" in line:
                alerts.append("[AUTH] su session opened")
            if "su:" in line and "authentication failure" in line:
                alerts.append("[AUTH] su authentication failure")

#           -------------------------------
#           Root login detection
#           -------------------------------
            if "session opened for user root" in line:
                alerts.append("[AUTH] ROOT LOGIN detected!")

#           -------------------------------
#           TTY Suspicious activity
#           -------------------------------
            if "tty" in line.lower() and "session opened" in line:
                if not ("pts/" in line or "tty1" in line):
                    alerts.append("[AUTH] Login from suspicious TTY")

        # brute force detection
        for key, count in failed_count.items():
            if count >= 5:
                user, ip = key.split(":")
                alerts.append(f"[AUTH] Possible BRUTE FORCE on {user} from {ip} ({count} failures)")

        self.baseline["known_ssh_ips"] = ssh_ips
        self.save_baseline()
        return alerts, events

    def extract_ip(self, line):
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        return match.group(1) if match else "unknown"

    def extract_user(self, line):
        match = re.search(r"for (\w+)", line)
        return match.group(1) if match else "unknown"

    def extract_sudo_user(self, line):
        match = re.search(r"sudo: (\w+)", line)
        return match.group(1) if match else "unknown"
