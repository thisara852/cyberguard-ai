import numpy as np
import pickle
import os
from typing import Dict, Any, Optional
from sklearn.ensemble import IsolationForest

from app.core.config import settings
from app.services.synthetic_data_generator import generate_synthetic_events

class AnomalyDetectionEngine:
    """Unsupervised Anomaly Detection using Isolation Forest (FR-11)."""

    def __init__(self):
        self.model = None
        self.model_version = "1.0.0"
        self.model_name = "CyberGuard-IsolationForest"
        self.is_fitted = False

    def _extract_numerical_features(self, event: Dict[str, Any]) -> np.ndarray:
        duration = float(event.get("duration", 0.1))
        bytes_sent = float(event.get("bytes_sent", 0))
        bytes_rcvd = float(event.get("bytes_received", 0))
        packets = float(event.get("packet_count", 1))
        dst_port = float(event.get("destination_port", 80))
        byte_ratio = (bytes_sent + 1.0) / (bytes_rcvd + 1.0)
        packet_rate = packets / max(duration, 0.001)

        return np.array([
            duration, bytes_sent, bytes_rcvd, packets, dst_port,
            byte_ratio, packet_rate
        ], dtype=np.float32)

    def fit_model(self, sample_count: int = 1000):
        """Fit unsupervised Isolation Forest on baseline network observations."""
        events = generate_synthetic_events(sample_count)
        # Train mostly on normal events
        normal_events = [e for e in events if e.get("attack_type") == "Normal"]
        X = np.array([self._extract_numerical_features(e) for e in normal_events])

        iso = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        iso.fit(X)
        self.model = iso
        self.is_fitted = True

        artifact_path = os.path.join(settings.MODEL_STORAGE_DIR, f"anomaly_iso_v{self.model_version}.pkl")
        with open(artifact_path, "wb") as f:
            pickle.dump(self.model, f)

    def score_event(self, event: Dict[str, Any]) -> float:
        """Compute continuous anomaly score between 0.0 (normal) and 1.0 (highly anomalous)."""
        if not self.is_fitted or self.model is None:
            artifact_path = os.path.join(settings.MODEL_STORAGE_DIR, f"anomaly_iso_v{self.model_version}.pkl")
            if os.path.exists(artifact_path):
                try:
                    with open(artifact_path, "rb") as f:
                        self.model = pickle.load(f)
                    self.is_fitted = True
                except Exception:
                    self.fit_model()
            else:
                self.fit_model()

        feat = self._extract_numerical_features(event).reshape(1, -1)
        # score_samples returns negative anomaly score: higher = more normal
        raw_score = self.model.score_samples(feat)[0]
        # Normalize into 0..1 scale where 1 is highest anomaly
        normalized_anomaly = float(1.0 / (1.0 + np.exp(raw_score * 5.0)))
        return round(normalized_anomaly, 4)

anomaly_engine = AnomalyDetectionEngine()
