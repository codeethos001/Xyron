import os
import hashlib
import json

class CronMonitor:
    def __init__(self, config):
        self.baseline_file = os.path.join(config["paths"]["baseline_dir"], "cron_baseline.json")
        self.cron_dirs = ["/etc/cron.d", "/var/spool/cron/crontabs", "/etc/crontab"]
        self.baseline = self.load_baseline()

    def load_baseline(self):
        if os.path.exists(self.baseline_file):
            with open(self.baseline_file, "r") as f:
                return json.load(f)
        return {}

    def save_baseline(self):
        with open(self.baseline_file, "w") as f:
            json.dump(self.baseline, f, indent=4)

    def hash_file(self, path):
        try:
            with open(path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return None

    def scan(self):
        alerts = []
        current_state = {}

        for p in self.cron_dirs:
            if os.path.isfile(p):
                current_state[p] = self.hash_file(p)
            elif os.path.isdir(p):
                for f in os.listdir(p):
                    fp = os.path.join(p, f)
                    current_state[fp] = self.hash_file(fp)

        # Compare
        for path, h in current_state.items():
            if path not in self.baseline:
                alerts.append(f"New Cron Job Found: {path}")
            elif self.baseline[path] != h:
                alerts.append(f"Cron Job Modified: {path}")

        self.baseline = current_state
        self.save_baseline()
        return alerts, []
    