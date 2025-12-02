import json
import hashlib
import os

class UserMonitor:
    def __init__(self, config):
        self.baseline_file = os.path.join(config["paths"]["baseline_dir"], "user_baseline.json")
        self.baseline = self.load_baseline()

    def load_baseline(self):
        if os.path.exists(self.baseline_file):
            with open(self.baseline_file, "r") as f:
                return json.load(f)
        return {}

    def save_baseline(self):
        with open(self.baseline_file, "w") as f:
            json.dump(self.baseline, f, indent=4)

    def get_users(self):
        users = set()
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    users.add(line.split(":")[0])
        except: pass
        return users

    def scan(self):
        alerts = []
        current_users = list(self.get_users())
        
        # Initial run
        if not self.baseline:
            self.baseline = {"users": current_users}
            self.save_baseline()
            return [], []

        old_users = set(self.baseline.get("users", []))
        new_users = set(current_users)

        added = new_users - old_users
        removed = old_users - new_users

        for u in added:
            alerts.append(f"New User Created: {u}")
        for u in removed:
            alerts.append(f"User Deleted: {u}")

        self.baseline["users"] = current_users
        self.save_baseline()
        return alerts, []