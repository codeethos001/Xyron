import hashlib
import os
import json

class FileIntegrityMonitor:
    def __init__(self, config):
        self.paths = config["paths"]["fim_targets"]
        self.baseline_file = os.path.join(config["paths"]["baseline_dir"], "file_baseline.json")
        self.baseline = self.load_baseline()

    def load_baseline(self):
        if not os.path.exists(self.baseline_file):
            return {}
        try:
            with open(self.baseline_file, "r") as f:
                return json.load(f)
        except:
            return {}

    def save_baseline(self):
        # Atomic Write: Write to .tmp then rename
        tmp_file = self.baseline_file + ".tmp"
        try:
            with open(tmp_file, "w") as f:
                json.dump(self.baseline, f, indent=4)
            os.replace(tmp_file, self.baseline_file)
        except Exception as e:
            print(f"[ERROR] Failed to save FIM baseline: {e}")

    def hash_file(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk: break
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None

    def scan(self):
        alerts = []
        events = []
        current_state = {}

        for path in self.paths:
            if os.path.isfile(path):
                file_hash = self.hash_file(path)
                current_state[path] = file_hash
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for name in files:
                        fp = os.path.join(root, name)
                        file_hash = self.hash_file(fp)
                        current_state[fp] = file_hash

        # Compare
        for path, hsh in current_state.items():
            if path not in self.baseline:
                alerts.append(f"NEW FILE: {path}")
                events.append(f"FIM_NEW: {path}")
            elif self.baseline[path] != hsh:
                alerts.append(f"MODIFIED FILE: {path}")
                events.append(f"FIM_MOD: {path}")

        for old_path in list(self.baseline.keys()):
            if old_path not in current_state:
                alerts.append(f"DELETED FILE: {old_path}")
                events.append(f"FIM_DEL: {old_path}")

        self.baseline = current_state
        self.save_baseline()
        return alerts, events