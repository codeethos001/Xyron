import re

class SignatureEngine:
    def __init__(self):
        # Define simple regex signatures
        self.signatures = [
            {"id": 1001, "name": "Shadow File Access", "pattern": r"cat /etc/shadow", "severity": "HIGH"},
            {"id": 1002, "name": "Netcat Reverse Shell", "pattern": r"nc -e /bin/sh", "severity": "CRITICAL"},
            {"id": 1003, "name": "Bash TCP Connect", "pattern": r"/dev/tcp/", "severity": "HIGH"},
            {"id": 1004, "name": "Base64 Decoded Exec", "pattern": r"base64 -d \| bash", "severity": "CRITICAL"},
            {"id": 1005, "name": "Root Kit Module Load", "pattern": r"insmod rootkit", "severity": "CRITICAL"}
        ]

    def check_event(self, event_text):
        if not isinstance(event_text, str):
            return None
            
        for sig in self.signatures:
            if re.search(sig["pattern"], event_text, re.IGNORECASE):
                return f"Signature Match: {sig['name']} (ID: {sig['id']})"
        return None