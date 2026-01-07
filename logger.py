import json
import os
from datetime import datetime


class AlertLogger:
    def __init__(self, filename="alerts.json"):
        # Always save logs next to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.filepath = os.path.join(base_dir, filename)

    def log(self, src_ip, attack_type, description):
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "attack_type": attack_type,
            "description": description
        }

        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
