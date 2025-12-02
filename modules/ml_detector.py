import numpy as np
import time

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
        self.last_train_time = time.time()
        
    def extract_features(self, event_data):
        """
        Convert raw event strings/dicts into a numerical vector.
        Feature vector: [is_root, length, is_failure, is_network_event]
        """
        try:
            if isinstance(event_data, str):
                is_root = 1 if "root" in event_data else 0
                length = len(event_data)
                is_failure = 1 if "fail" in event_data.lower() else 0
                is_net = 1 if "[NET]" in event_data else 0
                return [is_root, length, is_failure, is_net]
            elif isinstance(event_data, dict):
                is_root = 1 if event_data.get("user") == "root" else 0
                val = event_data.get("value", 0)
                return [is_root, val, 0, 0]
        except:
            return [0, 0, 0, 0]
        return [0, 0, 0, 0]

    def add_data_point(self, event_data):
        if not self.enabled:
            return
        
        features = self.extract_features(event_data)
        self.data_buffer.append(features)

    def analyze(self):
        """
        Train on buffered data and find outliers.
        """
        # Require at least 100 data points before trying to predict anything
        if not self.enabled or len(self.data_buffer) < 100:
            return []

        anomalies = []
        data = np.array(self.data_buffer)

        # Retrain model every 5 minutes or if we have a lot of new data
        now = time.time()
        if not self.is_trained or (now - self.last_train_time > 300) or len(self.data_buffer) > 500:
            # Contamination=0.01 means we assume only 1% of events are anomalies (Less False Positives)
            self.model = IsolationForest(contamination=0.01, random_state=42)
            self.model.fit(data)
            self.is_trained = True
            self.last_train_time = now
            
            # Keep the last 200 events as memory for the next batch
            self.data_buffer = self.data_buffer[-200:]
            return ["ML Model Retrained - Baseline Updated"]

        # Predict
        predictions = self.model.predict(data)
        
        # -1 indicates anomaly
        anomaly_indices = [i for i, x in enumerate(predictions) if x == -1]
        
        # Only alert if we have a significant cluster of anomalies (more than 3)
        if len(anomaly_indices) > 3:
            anomalies.append(f"Detected {len(anomaly_indices)} anomalous events (Pattern deviation)")

        return anomalies