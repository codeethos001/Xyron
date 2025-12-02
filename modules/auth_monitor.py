import os
import json
import re
import subprocess
import time

class AuthMonitor:
    def __init__(self, config):
        self.baseline_file = os.path.join(config["paths"]["baseline_dir"], "auth_baseline.json")
        self.use_journal = False
        self.log_path = None

        # State tracking for Brute Force Detection
        # Key: (user, ip) -> Value: list of timestamps
        self.failed_attempts = {}
        # Key: (user, ip) -> Value: timestamp of last brute force alert
        self.bf_last_alert = {}
        
        # Thresholds
        self.bf_window = 60  # seconds
        self.bf_threshold = 5 # attempts

        # 1. Try to find standard log files (Debian/Ubuntu/RHEL)
        if os.path.exists("/var/log/auth.log"):
            self.log_path = "/var/log/auth.log"
        elif os.path.exists("/var/log/secure"):
            self.log_path = "/var/log/secure"
        else:
            # 2. Fallback to systemd-journald (Arch Linux/Fedora)
            self.use_journal = True
            
        self.baseline = self.load_baseline()

    def load_baseline(self):
        if not os.path.exists(self.baseline_file):
            # For journalctl, we track the timestamp. For files, we track byte position.
            return {"last_pos": 0, "last_journal_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
        try:
            with open(self.baseline_file, "r") as f:
                data = json.load(f)
                # Ensure keys exist if upgrading from old version
                if "last_journal_timestamp" not in data:
                    data["last_journal_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                return data
        except:
            return {"last_pos": 0, "last_journal_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

    def save_baseline(self):
        # Atomic Write Pattern
        tmp_file = self.baseline_file + ".tmp"
        try:
            with open(tmp_file, "w") as f:
                json.dump(self.baseline, f, indent=4)
            os.replace(tmp_file, self.baseline_file)
        except Exception:
            pass

    def get_journal_logs(self):
        """
        Fetch recent auth logs using journalctl for Arch Linux.
        """
        logs = []
        last_ts = self.baseline.get("last_journal_timestamp")
        
        # Update timestamp for next run immediately
        self.baseline["last_journal_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")

        try:
            # Command: Get logs from syslog facility 4 (auth) and 10 (authpriv)
            # --since: Only get logs since the last scan
            cmd = [
                "journalctl",
                "--since", last_ts,
                "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10",
                "--no-pager",
                "--output=short"
            ]
            
            # Execute command
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            decoded = result.decode("utf-8", errors="ignore")
            
            if decoded:
                logs = decoded.strip().split("\n")
                
        except Exception as e:
            # Command might fail if journalctl isn't installed or perm issues
            pass
            
        return logs

    def get_file_logs(self):
        """
        Fetch logs from /var/log/auth.log or /var/log/secure.
        """
        lines = []
        if not self.log_path:
            return lines

        try:
            current_size = os.path.getsize(self.log_path)
            # Handle log rotation
            if current_size < self.baseline["last_pos"]:
                self.baseline["last_pos"] = 0

            with open(self.log_path, "r") as f:
                f.seek(self.baseline["last_pos"])
                lines = f.readlines()
                self.baseline["last_pos"] = f.tell()
        except Exception:
            pass
            
        return lines

    def scan(self):
        alerts = []
        events = []
        now = time.time()

        # Get lines from either Journalctl or File
        if self.use_journal:
            new_lines = self.get_journal_logs()
        else:
            new_lines = self.get_file_logs()

        for line in new_lines:
            # 1. Failed Passwords (BRUTE FORCE LOGIC)
            if "Failed password" in line:
                user = self.extract_user(line)
                ip = self.extract_ip(line)
                key = (user, ip)

                # Initialize if not exists
                if key not in self.failed_attempts:
                    self.failed_attempts[key] = []

                # Add current attempt
                self.failed_attempts[key].append(now)

                # Clean up old attempts (sliding window)
                # Keep only attempts within the last bf_window seconds
                self.failed_attempts[key] = [t for t in self.failed_attempts[key] if now - t < self.bf_window]
                
                count = len(self.failed_attempts[key])

                if count >= self.bf_threshold:
                    # Check cooldown to avoid spamming "Brute Force" alert too
                    last_alert = self.bf_last_alert.get(key, 0)
                    if now - last_alert > self.bf_window:
                        alerts.append(f"Possible BRUTE FORCE for {user} from {ip} ({count} failures in {self.bf_window}s)")
                        self.bf_last_alert[key] = now
                        events.append(f"AUTH_BRUTE_FORCE user={user} ip={ip} count={count}")
                    # Note: We do NOT append the individual "Failed login" alert here to prevent spam
                else:
                    # Low volume - log individual failure
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
                
            # 4. SSH Accepted Password (Successful Login)
            if "Accepted password" in line:
                user = self.extract_user(line)
                ip = self.extract_ip(line)
                events.append(f"AUTH_LOGIN_SUCCESS user={user} ip={ip}")
                
                # Reset failed attempts logic on success
                key = (user, ip)
                if key in self.failed_attempts:
                    del self.failed_attempts[key]

        self.save_baseline()
        return alerts, events

    def extract_ip(self, line):
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        return match.group(1) if match else "unknown"

    def extract_user(self, line):
        # Regex to catch 'for <user>' pattern
        match = re.search(r"for (\w+)", line)
        # Fallback for some journal formats that might say 'user <user>'
        if not match:
            match = re.search(r"user (\w+)", line)
        return match.group(1) if match else "unknown"
        
    def extract_sudo_user(self, line):
        match = re.search(r"sudo: \s*(\w+)", line)
        return match.group(1) if match else "unknown" 