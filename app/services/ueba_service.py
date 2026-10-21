from datetime import datetime
from typing import Dict, Any, List

class UEBAEngine:
    """User & Entity Behavior Analytics (UEBA) baseline & deviation detector (FR-29, FR-30)."""

    def __init__(self):
        # Baseline expectations
        self.normal_hour_start = 8   # 08:00 AM
        self.normal_hour_end = 19    # 07:00 PM
        self.max_normal_bytes = 15 * 1024 * 1024 # 15 MB

    def evaluate_behavior(
        self,
        entity_id: str,
        timestamp: datetime,
        bytes_transferred: int,
        source_ip: str,
        entity_role: str = "User"
    ) -> Dict[str, Any]:
        """Detect deviations from established behavior baselines (FR-30)."""
        hour = timestamp.hour
        is_after_hours = hour < self.normal_hour_start or hour > self.normal_hour_end
        is_deep_night = 0 <= hour <= 4

        anomaly_points = 0.0
        indicators = []

        if is_deep_night:
            anomaly_points += 40
            indicators.append(f"Unusual deep-night activity ({timestamp.strftime('%H:%M')} UTC)")
        elif is_after_hours:
            anomaly_points += 20
            indicators.append(f"Activity outside standard operational hours ({timestamp.strftime('%H:%M')} UTC)")

        if bytes_transferred > self.max_normal_bytes:
            mb = round(bytes_transferred / (1024 * 1024), 2)
            anomaly_points += 45
            indicators.append(f"Massive data volume detected: {mb}MB transferred (baseline < 15MB)")

        # External IP check for privileged accounts
        if entity_role in ["Super Admin", "Admin"] and not source_ip.startswith(("192.168.", "10.", "172.16.")):
            anomaly_points += 30
            indicators.append(f"Privileged admin access originating from non-corporate external IP ({source_ip})")

        behavior_anomaly_score = min(round(anomaly_points, 1), 100.0)
        is_anomalous = behavior_anomaly_score >= 40.0

        return {
            "entity_id": entity_id,
            "behavior_anomaly_score": behavior_anomaly_score,
            "is_anomalous": is_anomalous,
            "indicators": indicators if indicators else ["Activity consistent with baseline profile"]
        }

ueba_engine = UEBAEngine()
