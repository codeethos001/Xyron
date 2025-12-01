import os
import hashlib
import json

BASELINE_FILE = "baseline/cron_baseline.json"

SYSTEM_CRON = [
    "/etc/crontab",
    "/etc/cron.d"
]

USER_CRON_DIR = "/var/spool/cron"

class CronMonitor:
    def __init__(self):
        self.baseline = self.load_baseline()

    def load_baseline(self):
        if not os.path.exists(BASELINE_FILE):
            return {}
        try:
            with open(BASELINE_FILE, "r") as f:
                return json.load(f)
        except:
            return {}

    def save_baseline(self):
        with open(BASELINE_FILE, "w") as f:
            json.dump(self.baseline, f, indent=4)

    def hash_file(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None

    def collect_cron_files(self):
        cron_files = []

        # System cron: /etc/crontab
        if os.path.isfile("/etc/crontab"):
            cron_files.append("/etc/crontab")

        # /etc/cron.d directory
        if os.path.isdir("/etc/cron.d"):
            for f in os.listdir("/etc/cron.d"):
                fp = os.path.join("/etc/cron.d", f)
                if os.path.isfile(fp):
                    cron_files.append(fp)

        # User crons: /var/spool/cron/*
        if os.path.isdir(USER_CRON_DIR):
            for f in os.listdir(USER_CRON_DIR):
                fp = os.path.join(USER_CRON_DIR, f)
                if os.path.isfile(fp):
                    cron_files.append(fp)

        return cron_files

    def scan(self):
        alerts = []
        events = []

        cron_files = self.collect_cron_files()
        current_state = {}

        # Hash all cron files
        for path in cron_files:
            h = self.hash_file(path)
            current_state[path] = h

            if path not in self.baseline:
                alerts.append(f"[CRON] NEW cron file: {path}")
                events.append(f"NEW CRON FILE: {path}")
            elif self.baseline[path] != h:
                alerts.append(f"[CRON] Modified cron file: {path}")
                events.append(f"MODIFIED CRON: {path}")

        # Deleted cron files
        for old_path in list(self.baseline.keys()):
            if old_path not in current_state:
                alerts.append(f"[CRON] Deleted cron file: {old_path}")
                events.append(f"DELETED CRON: {old_path}")

        # Update baseline
        self.baseline = current_state
        self.save_baseline()

        return alerts, events
