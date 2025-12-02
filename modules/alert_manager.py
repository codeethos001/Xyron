import logging
import json
import os
import time
import re

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
        
        clean_msg = f"[{module_name.upper()}] [{severity.upper()}] {message}"
        if details:
            clean_msg += f" | Details: {json.dumps(details)}"
        logging.info(clean_msg)

        # 2. Fancy String for Console
        if self.console:
            # Color Constants
            RESET = "\033[0m"
            GREY = "\033[90m"
            RED = "\033[91m"
            GREEN = "\033[92m"
            YELLOW = "\033[93m"
            BLUE = "\033[94m"
            CYAN = "\033[96m"

            # Colorize Timestamp
            ts_colored = f"{GREY}{timestamp}{RESET}"

            # Colorize Module Name
            mod_colored = f"{CYAN}[{module_name.upper()}]{RESET}"

            # Colorize Severity Tag ONLY
            sev = severity.lower()
            if sev in ["high", "critical", "error"]:
                sev_color = RED
            elif sev in ["medium", "warning"]:
                sev_color = YELLOW
            else:
                sev_color = GREEN
            
            sev_colored = f"{sev_color}[{severity.upper()}]{RESET}"

            # Colorize Message Content (IPs and MACs)
            msg_colored = message
            
            # Regex for IPv4
            msg_colored = re.sub(
                r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', 
                f'{BLUE}\\1{RESET}', 
                msg_colored
            )
            
            # Regex for MAC Addresses
            msg_colored = re.sub(
                r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})',
                f'{BLUE}\\1{RESET}',
                msg_colored
            )

            if details:
                msg_colored += f" | Details: {json.dumps(details)}"

            # Print Final Formatted String
            print(f"{ts_colored} {mod_colored} {sev_colored} {msg_colored}")

    def log_event(self, message):
        if self.console:
            print(f"[EVENT] {message}")