import psutil
import time

class ProcessMonitor:
    def __init__(self, config):
        self.prev_pids = set()
        self.suspicious_paths = ["/tmp", "/var/tmp", "/dev/shm"]
        self.cpu_threshold = config["thresholds"]["cpu_usage"]

    def scan(self):
        alerts = []
        events = [] # For ML

        current_pids = set(psutil.pids())
        new_pids = current_pids - self.prev_pids

        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                exe = p.exe() if p.exe() else "unknown"
                name = p.name()
                cmdline = " ".join(p.cmdline())
                user = p.username()
                
                # Structure event for ML
                events.append(f"PROCESS_START: user={user} cmd={cmdline}")

                # 1. Suspicious Path Check
                if any(exe.startswith(path) for path in self.suspicious_paths):
                    alerts.append(f"Suspicious Execution Path: PID {pid} ({exe})")

                # 2. CPU Usage Check (Brief check, better done continuously)
                if p.cpu_percent(interval=0.1) > self.cpu_threshold:
                    alerts.append(f"High CPU Usage: PID {pid} ({name})")
                
                # 3. Common Attack Tools
                if name in ["nc", "ncat", "netcat", "nmap", "wireshark", "tcpdump"]:
                    alerts.append(f"Attack Tool Detected: {name} (PID {pid})")

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.prev_pids = current_pids
        return alerts, events