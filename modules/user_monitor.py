import json
import hashlib
import os

BASELINE_FILE = "baseline/user_baseline.json"

WATCH_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers"
]

class UserMonitor:
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

    def parse_passwd(self):
        users = {}
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    parts = line.strip().split(":")
                    user = parts[0]
                    uid = parts[2]
                    gid = parts[3]
                    home = parts[5]
                    shell = parts[6]
                    users[user] = {
                        "uid": uid,
                        "gid": gid,
                        "home": home,
                        "shell": shell
                    }
        except:
            pass
        return users

    def parse_group(self):
        groups = {}
        try:
            with open("/etc/group", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    grp = parts[0]
                    members = parts[3].split(",") if parts[3] else []
                    groups[grp] = members
        except:
            pass
        return groups

    def scan(self):
        alerts = []
        events = []

        # Hash all important files
        file_hashes = {}
        for path in WATCH_FILES:
            file_hashes[path] = self.hash_file(path)

        # Parse users & groups
        current_users = self.parse_passwd()
        current_groups = self.parse_group()

        baseline_users = self.baseline.get("users", {})
        baseline_groups = self.baseline.get("groups", {})
        baseline_files = self.baseline.get("file_hashes", {})

        # Detect file modifications
        for path, h in file_hashes.items():
            if path not in baseline_files:
                alerts.append(f"[USER] New monitored file detected: {path}")
            elif baseline_files[path] != h:
                alerts.append(f"[USER] File changed: {path}")

        # User additions
        for user in current_users:
            if user not in baseline_users:
                alerts.append(f"[USER] New user added: {user}")
                events.append(f"NEW USER: {user}")

        # User deletions
        for user in baseline_users:
            if user not in current_users:
                alerts.append(f"[USER] User deleted: {user}")
                events.append(f"DELETED USER: {user}")

        # User modifications
        for user, info in current_users.items():
            if user in baseline_users:
                base = baseline_users[user]

                # UID change
                if info["uid"] != base["uid"]:
                    alerts.append(f"[USER] UID changed for {user}")

                # Shell change
                if info["shell"] != base["shell"]:
                    alerts.append(f"[USER] Shell changed for {user}: {base['shell']} → {info['shell']}")

                # Suspicious: UID 0 but not root
                if info["uid"] == "0" and user != "root":
                    alerts.append(f"[USER] Suspicious UID=0 for user: {user}")

        # Group additions
        for grp in current_groups:
            if grp not in baseline_groups:
                alerts.append(f"[USER] New group added: {grp}")

        # Group deletions
        for grp in baseline_groups:
            if grp not in current_groups:
                alerts.append(f"[USER] Group deleted: {grp}")

        # Sudo user detection
        sudo_members = current_groups.get("sudo", []) + current_groups.get("wheel", [])
        for user in sudo_members:
            if user not in baseline_groups.get("sudo", []) and user not in baseline_groups.get("wheel", []):
                alerts.append(f"[USER] User gained sudo privileges: {user}")

        # Update baseline
        self.baseline = {
            "users": current_users,
            "groups": current_groups,
            "file_hashes": file_hashes
        }
        self.save_baseline()

        return alerts, events
