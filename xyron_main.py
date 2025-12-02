import time
import json
import threading
import os
import queue
from modules.alert_manager import AlertManager
from modules.process_monitor import ProcessMonitor
from modules.file_integrity import FileIntegrityMonitor
from modules.net_monitor import NetworkMonitor
from modules.auth_monitor import AuthMonitor
from modules.user_monitor import UserMonitor
from modules.cron_monitor import CronMonitor
from modules.ml_detector import MachineLearningDetector
from modules.signature_engine import SignatureEngine

# Load Config
def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

CONFIG = load_config()

# Ensure directories exist
os.makedirs(CONFIG["paths"]["baseline_dir"], exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Initialize Core Systems
alerts = AlertManager(CONFIG)
event_queue = queue.Queue() # For ML processing

# Initialize Modules
process_mon = ProcessMonitor(CONFIG)
fim_mon = FileIntegrityMonitor(CONFIG)
net_mon = NetworkMonitor(CONFIG, alerts) # Network needs direct alert access for callbacks
auth_mon = AuthMonitor(CONFIG)
user_mon = UserMonitor(CONFIG)
cron_mon = CronMonitor(CONFIG)
ml_engine = MachineLearningDetector(CONFIG)
sig_engine = SignatureEngine()

def run_network_monitor():
    """Runs Scapy in a separate thread because it blocks."""
    try:
        net_mon.start()
    except Exception as e:
        alerts.log_alert("NETWORK", "ERROR", f"Network monitor failed: {e}")

def main_loop():
    print(f"[*] Xyron HIDS initialized. PID: {os.getpid()}")
    
    # Start Network Thread
    net_thread = threading.Thread(target=run_network_monitor, daemon=True)
    net_thread.start()

    last_checks = {
        "process": 0,
        "fim": 0,
        "auth": 0,
        "user": 0,
        "cron": 0,
        "ml": 0
    }

    try:
        while True:
            now = time.time()

            # --- Process Monitor ---
            if now - last_checks["process"] > CONFIG["monitor_intervals"]["process"]:
                proc_alerts, proc_events = process_mon.scan()
                for alert in proc_alerts:
                    alerts.log_alert("PROCESS", "HIGH", alert)
                for event in proc_events:
                    event_queue.put(event) # Feed to ML
                last_checks["process"] = now

            # --- File Integrity Monitor ---
            if now - last_checks["fim"] > CONFIG["monitor_intervals"]["fim"]:
                fim_alerts, _ = fim_mon.scan()
                for alert in fim_alerts:
                    alerts.log_alert("FIM", "CRITICAL", alert)
                last_checks["fim"] = now

            # --- Auth Monitor ---
            if now - last_checks["auth"] > CONFIG["monitor_intervals"]["auth"]:
                auth_alerts, auth_events = auth_mon.scan()
                for alert in auth_alerts:
                    alerts.log_alert("AUTH", "HIGH", alert)
                for event in auth_events:
                    event_queue.put(event)
                last_checks["auth"] = now

            # --- User/Group Monitor ---
            if now - last_checks["user"] > CONFIG["monitor_intervals"]["user"]:
                user_alerts, _ = user_mon.scan()
                for alert in user_alerts:
                    alerts.log_alert("USER", "MEDIUM", alert)
                last_checks["user"] = now

            # --- Cron Monitor ---
            if now - last_checks["cron"] > CONFIG["monitor_intervals"]["cron"]:
                cron_alerts, _ = cron_mon.scan()
                for alert in cron_alerts:
                    alerts.log_alert("CRON", "MEDIUM", alert)
                last_checks["cron"] = now

            # --- ML Anomaly Detection & Signature Check ---
            # Process accumulated events
            while not event_queue.empty():
                event_data = event_queue.get()
                
                # Check Signatures
                sig_alert = sig_engine.check_event(event_data)
                if sig_alert:
                    alerts.log_alert("SIGNATURE", "HIGH", sig_alert)

                # Feed to ML
                ml_engine.add_data_point(event_data)

            # Periodically train/predict ML
            if now - last_checks["ml"] > CONFIG["monitor_intervals"]["ml_training"]:
                ml_anomalies = ml_engine.analyze()
                for anomaly in ml_anomalies:
                    alerts.log_alert("ML_AI", "WARNING", anomaly)
                last_checks["ml"] = now

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Stopping Xyron HIDS...")

if __name__ == "__main__":
    main_loop()