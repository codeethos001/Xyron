import hashlib
import os
import json
import time

BASELINE_FILE = "baseline/file_baseline.json"

class FileIntegrityMonitor:
    def __init__(self, paths_to_watch):
        self.paths = paths_to_watch
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

    def scan(self):
        alerts = []
        events = []
        current_state = {}

        # Gather current file hashes
        for path in self.paths:
            if os.path.isfile(path):
                file_hash = self.hash_file(path)
                current_state[path] = file_hash
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for name in files:
                        fp = os.path.join(root, name)
                        file_hash = self.hash_file(fp)
                        current_state[fp] = file_hash

        # Compare with baseline
        for path, hsh in current_state.items():

            # New file
            if path not in self.baseline:
                alerts.append(f"[FIM] NEW FILE: {path}")
                events.append(f"NEW FILE: {path}")
            
            # Modified file
            elif self.baseline[path] != hsh:
                alerts.append(f"[FIM] MODIFIED FILE: {path}")
                events.append(f"MODIFIED: {path}")

        # Deleted file
        for old_path in list(self.baseline.keys()):
            if old_path not in current_state:
                alerts.append(f"[FIM] DELETED FILE: {old_path}")
                events.append(f"DELETED: {old_path}")

        # Update baseline after scan
        self.baseline = current_state
        self.save_baseline()

        return alerts, events