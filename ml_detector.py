import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
import time
from collections import defaultdict
from scapy.layers.inet import TCP, ICMP

class MLAnomalyDetector:
    def __init__(self, model_path="ml_model.pkl"):
        self.model_path = model_path

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        self.threshold = -0.5
        self.trained = False
        self.feature_buffer = []
        self.ip_activity = defaultdict(lambda: {
            "packet_count": 0,
            "ports": set(),
            "icmp": 0,
            "start_time": time.time()
        })

        self.load_model()


    def extract_features(self, src_ip, packet):
        record = self.ip_activity[src_ip]

        record["packet_count"] += 1



        if TCP in packet:
            record["ports"].add(packet[TCP].dport)

        if ICMP in packet:
            record["icmp"] += 1

        duration = time.time() - record["start_time"]

        features = [
            record["packet_count"],
            len(record["ports"]),
            record["icmp"],
            duration
        ]

        return features

    def collect(self, features):
        self.feature_buffer.append(features)

        if len(self.feature_buffer) >= 50 and not self.trained:
            self.train()

    def train(self):
        X = np.array(self.feature_buffer)
        self.model.fit(X)
        self.trained = True
        self.save_model()
        print("🤖 ML model trained on normal traffic")

    def predict(self, features):
        if not self.trained:
            return None, None

        score = self.model.decision_function([features])[0]

        # Explainable threshold-based decision
        is_anomaly = score < self.threshold

        return is_anomaly, score

    def load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            self.trained = True
            print("📂 ML model loaded from disk")

    def get_severity(self, score):
        if score is None:
            return "NORMAL"

        if score < -1.0:
            return "HIGH"
        elif score < -0.7:
            return "MEDIUM"
        elif score < self.threshold:
            return "LOW"
        else:
            return "NORMAL"
