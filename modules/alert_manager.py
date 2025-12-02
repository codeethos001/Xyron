import logging
import json
import os
import time

class AlertManager:
    def __init__(self, config):
        self.log_file = config["logging"]["log_file"]
        self.console = config["logging"]["console_output"]
        self.setup_logger()

    def setup_logger(self):
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def log_alert(self, module_name, severity, message, details=None):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert_str = f"[{module_name.upper()}] [{severity.upper()}] {message}"
        
        if details:
            alert_str += f" | Details: {json.dumps(details)}"

        # Log to file
        logging.info(alert_str)

        # Print to console
        if self.console:
            color = "\033[91m" if severity == "high" else "\033[93m" if severity == "medium" else "\033[92m"
            reset = "\033[0m"
            print(f"{color}{timestamp} {alert_str}{reset}")

    def log_event(self, message):
        if self.console:
            print(f"[EVENT] {message}")