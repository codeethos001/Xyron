import os
import re

AUDIT_LOG = "/var/log/audit/audit.log"
SYSLOG = "/var/log/syslog"    # fallback for Debian
MESSAGES = "/var/log/messages"  # fallback for RHEL/Arch

CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config"
]

SUSPICIOUS_DIRS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm"
]

class AuditMonitor:
    def __init__(self):
        self.log_path = self.detect_log_file()
        self.last_pos = 0

    def detect_log_file(self):
        if os.path.exists(AUDIT_LOG):
            return AUDIT_LOG
        elif os.path.exists(SYSLOG):
            return SYSLOG
        elif os.path.exists(MESSAGES):
            return MESSAGES
        else:
            print("[AUDIT] No audit or syslog found!")
            return None

    def scan(self):
        alerts = []
        events = []

        if not self.log_path:
            return alerts, events

        with open(self.log_path, "r") as f:
            f.seek(self.last_pos)
            new_lines = f.readlines()
            self.last_pos = f.tell()

        for line in new_lines:

            # -----------------------------------------
            # Detect execution from temp directories
            # -----------------------------------------
            if "EXECVE" in line:
                for d in SUSPICIOUS_DIRS:
                    if d in line:
                        alerts.append(f"[AUDIT] Suspicious binary executed from {d}")
                        events.append(line.strip())

            # -----------------------------------------
            # Detect chmod/chown on critical files
            # -----------------------------------------
            if "chmod" in line or "chown" in line:
                for c in CRITICAL_FILES:
                    if c in line:
                        alerts.append(f"[AUDIT] Permission change attempt on {c}")
                        events.append(line.strip())

            # -----------------------------------------
            # Detect unauthorized write to critical files
            # -----------------------------------------
            if "write" in line or "open" in line:
                if "flags=O_WRONLY" in line or "flags=O_RDWR" in line:
                    for c in CRITICAL_FILES:
                        if c in line:
                            alerts.append(f"[AUDIT] Unauthorized write attempt: {c}")
                            events.append(line.strip())

            # -----------------------------------------
            # Detect log deletion (unlink)
            # -----------------------------------------
            if "unlink" in line and "/var/log" in line:
                alerts.append("[AUDIT] Log deletion attempt!")
                events.append(line.strip())

            # -----------------------------------------
            # Detect privilege escalation attempts
            # -----------------------------------------
            if "sudo" in line and "COMMAND" in line:
                alerts.append("[AUDIT] sudo command executed")
                events.append(line.strip())

            if "su:" in line and "session opened" in line:
                alerts.append("[AUDIT] su used to switch user")
                events.append(line.strip())

        return alerts, events
