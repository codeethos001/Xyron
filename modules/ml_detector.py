import numpy as np
from collections import deque

# Try importing sklearn, fallback if not present
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class MachineLearningDetector:
    def __init__(self, config):
        self.enabled = SKLEARN_AVAILABLE
        self.data_buffer = []
        self.model = None
        self.is_trained = False
        
        # We will extract simple numerical features from events
        # Feature vector: [hour_of_day, is_root_action (0/1), log_length]
        
    def extract_features(self, event_data):
        """
        Convert raw event strings/dicts into a numerical vector.
        This is a simplified feature extractor.
        """
        # Example event data: {"type": "process", "pid": 123, "user": "root", "time": 160000}
        # Or simple string: "NEW PROCESS: 1234 python3 root"
        
        try:
            # Simple heuristic extraction
            if isinstance(event_data, str):
                is_root = 1 if "root" in event_data else 0
                length = len(event_data)
                is_failure = 1 if "fail" in event_data.lower() else 0
                return [is_root, length, is_failure]
            elif isinstance(event_data, dict):
                # More structured extraction
                is_root = 1 if event_data.get("user") == "root" else 0
                val = event_data.get("value", 0)
                return [is_root, val, 0]
        except:
            return [0, 0, 0]
        return [0, 0, 0]

    def add_data_point(self, event_data):
        if not self.enabled:
            return
        
        features = self.extract_features(event_data)
        self.data_buffer.append(features)

    def analyze(self):
        """
        Train on buffered data and find outliers.
        """
        if not self.enabled or len(self.data_buffer) < 50:
            return []

        anomalies = []
        data = np.array(self.data_buffer)

        # Retrain model periodically
        if not self.is_trained or len(self.data_buffer) > 200:
            self.model = IsolationForest(contamination=0.05, random_state=42)
            self.model.fit(data)
            self.is_trained = True
            # Clear old buffer to keep memory low, keep last 50
            self.data_buffer = self.data_buffer[-50:]
            return ["ML Model Retrained"]

        # Predict
        predictions = self.model.predict(data)
        
        # -1 indicates anomaly
        anomaly_indices = [i for i, x in enumerate(predictions) if x == -1]
        
        if len(anomaly_indices) > 0:
            anomalies.append(f"Detected {len(anomaly_indices)} anomalous events based on behavior patterns.")

        return anomalies