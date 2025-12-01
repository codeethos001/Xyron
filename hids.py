import psutil
import time
import os

class ProcessMonitor:
    def __init__(self):
        self.prev_pids = set()
        self.suspicious_paths = ["/tmp", "/var/tmp", "/dev/shm"]

    def scan(self):
        alerts = []
        events = []

        current_pids = set(psutil.pids())
        new_pids = current_pids - self.prev_pids

        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                exe = p.exe() if p.exe() else "unknown"
                cpu = p.cpu_percent(interval=0.1)
                mem = p.memory_percent()
                user = p.username()

                events.append(f"NEW PROCESS: {p.pid} {p.name()} {exe}")

                # Suspicious path
                if any(exe.startswith(path) for path in self.suspicious_paths):
                    alerts.append(f"Process from suspicious path: PID {pid} ({exe})")

                # High CPU
                if cpu > 40:
                    alerts.append(f"High CPU usage: PID {pid} ({cpu}%)")


            except Exception:
                continue
        
        self.prev_pids = current_pids
        return alerts, events
