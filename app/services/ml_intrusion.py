import os
import pickle
import json
from typing import Dict, Any, Tuple, Optional
import numpy as np
from datetime import datetime
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import MLModelRecord, SecurityEvent, PredictionRecord
from app.services.synthetic_data_generator import generate_synthetic_events

# Protocol & Service mappings for feature encoding
PROTOCOLS = ["TCP", "UDP", "ICMP", "OTHER"]
SERVICES = ["http", "https", "dns", "ssh", "other"]
ATTACK_CLASSES = ["Normal", "DDoS", "PortScan", "BruteForce", "WebExploit", "Anomaly"]

class IntrusionDetectionEngine:
    """Supervised Machine Learning Engine for Network Intrusion Detection (FR-10, FR-16, FR-44)."""

    def __init__(self):
        self.model = None
        self.model_version = "1.0.0"
        self.model_name = "CyberGuard-RandomForest"
        self.metrics = {}
        self.is_trained = False

    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract and normalize numerical and categorical features into an ML vector (FR-09)."""
        duration = float(event.get("duration", 0.1))
        bytes_sent = float(event.get("bytes_sent", 0))
        bytes_rcvd = float(event.get("bytes_received", 0))
        packets = float(event.get("packet_count", 1))
        dst_port = float(event.get("destination_port", 80))

        # Engineered features
        byte_ratio = (bytes_sent + 1.0) / (bytes_rcvd + 1.0)
        packet_rate = packets / max(duration, 0.001)

        # One-hot encode protocol
        proto = str(event.get("protocol", "TCP")).upper()
        proto_encoded = [1.0 if proto == p else 0.0 for p in PROTOCOLS]

        # One-hot encode service
        svc = str(event.get("service", "http")).lower()
        svc_encoded = [1.0 if svc == s else 0.0 for s in SERVICES]

        feature_vector = [
            duration, bytes_sent, bytes_rcvd, packets, dst_port,
            byte_ratio, packet_rate
        ] + proto_encoded + svc_encoded

        return np.array(feature_vector, dtype=np.float32)

    def train_model(self, db: Optional[Session] = None, sample_count: int = 1500) -> Dict[str, Any]:
        """Train and evaluate Random Forest model on cybersecurity benchmark data (FR-44, FR-45)."""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

        # Generate training dataset
        dataset = generate_synthetic_events(sample_count)
        X = []
        y = []
        for record in dataset:
            feat = self.extract_features(record)
            label = record.get("attack_type", "Normal")
            X.append(feat)
            y.append(label)

        X = np.array(X)
        y = np.array(y)

        # Train/test split (80/20)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Train Random Forest Classifier
        clf = RandomForestClassifier(n_estimators=60, max_depth=12, random_state=42)
        clf.fit(X_train, y_train)

        # Evaluation metrics
        y_pred = clf.predict(X_test)
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
        rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()

        self.model = clf
        self.is_trained = True
        self.metrics = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
            "classes": list(clf.classes_)
        }

        # Save model artifact
        artifact_filename = f"intrusion_rf_v{self.model_version}.pkl"
        artifact_path = os.path.join(settings.MODEL_STORAGE_DIR, artifact_filename)
        with open(artifact_path, "wb") as f:
            pickle.dump(self.model, f)

        # Register in database if db session provided (FR-44, FR-47)
        if db:
            # Set any previous production models to non-production
            db.query(MLModelRecord).filter(
                MLModelRecord.model_name == self.model_name
            ).update({"is_production": False})

            record = MLModelRecord(
                model_name=self.model_name,
                version=self.model_version,
                algorithm="RandomForestClassifier",
                accuracy=acc,
                precision=prec,
                recall=rec,
                f1_score=f1,
                is_production=True,
                artifact_path=artifact_path,
                metrics_json=json.dumps(self.metrics),
                registered_at=datetime.utcnow()
            )
            db.add(record)
            db.commit()

        return self.metrics

    def predict(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Classify security event as normal or malicious with confidence (FR-10, FR-16)."""
        if not self.is_trained or self.model is None:
            artifact_path = os.path.join(settings.MODEL_STORAGE_DIR, f"intrusion_rf_v{self.model_version}.pkl")
            if os.path.exists(artifact_path):
                try:
                    with open(artifact_path, "rb") as f:
                        self.model = pickle.load(f)
                    self.is_trained = True
                except Exception:
                    self.train_model()
            else:
                self.train_model()

        feat = self.extract_features(event_dict).reshape(1, -1)
        pred_label = self.model.predict(feat)[0]
        probabilities = self.model.predict_proba(feat)[0]
        class_idx = list(self.model.classes_).index(pred_label)
        confidence = float(probabilities[class_idx])

        is_malicious = pred_label != "Normal"

        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "is_malicious": is_malicious,
            "threat_type": pred_label,
            "confidence": round(confidence, 4)
        }

# Global singleton instance
intrusion_engine = IntrusionDetectionEngine()
