from typing import Dict, Any, Tuple
from app.models.entities import MonitoredDevice

class RiskEngine:
    """Unified AI Composite Risk Engine (FR-17, FR-18, FR-31)."""

    SEVERITY_LEVELS = {
        "LOW": (0.0, 39.9),
        "MEDIUM": (40.0, 69.9),
        "HIGH": (70.0, 89.9),
        "CRITICAL": (90.0, 100.0)
    }

    ASSET_CRITICALITY_SCORES = {
        "CRITICAL": 25.0,
        "HIGH": 18.0,
        "MEDIUM": 10.0,
        "LOW": 5.0
    }

    def compute_risk(
        self,
        ml_prediction: Dict[str, Any],
        anomaly_score: float = 0.0,
        rule_threats: Dict[str, Any] = None,
        target_device: MonitoredDevice = None,
        ueba_score: float = 0.0
    ) -> Tuple[float, str, Dict[str, Any]]:
        """Calculate a 0–100 composite risk score with factor breakdown (FR-17, FR-31)."""
        rule_threats = rule_threats or {}
        breakdown = {}
        total_score = 0.0

        # Factor 1: Supervised ML Confidence & Malicious Threat Type (Weight: 40%)
        is_malicious = ml_prediction.get("is_malicious", False)
        ml_conf = ml_prediction.get("confidence", 0.0)
        threat_type = ml_prediction.get("threat_type", "Normal")

        if is_malicious:
            ml_points = round(ml_conf * 40.0, 2)
            total_score += ml_points
            breakdown["ml_intrusion_classification"] = {
                "points": ml_points,
                "threat_type": threat_type,
                "confidence": ml_conf,
                "detail": f"Classified as {threat_type} with {int(ml_conf * 100)}% ML confidence"
            }
        else:
            breakdown["ml_intrusion_classification"] = {"points": 0.0, "threat_type": "Normal"}

        # Factor 2: Unsupervised Anomaly Score (Weight: 25%)
        # anomaly_score is 0..1
        if anomaly_score > 0.4:
            anomaly_points = round(anomaly_score * 25.0, 2)
            total_score += anomaly_points
            breakdown["isolation_forest_anomaly"] = {
                "points": anomaly_points,
                "raw_score": anomaly_score,
                "detail": f"Unusual traffic deviation detected (Score: {anomaly_score})"
            }

        # Factor 3: Stateful Rule Engines (Brute-Force & Port-Scan) (Weight: 20%)
        rule_points = 0.0
        rule_reasons = []
        if rule_threats.get("is_brute_force"):
            rule_points += 15.0
            rule_reasons.append(rule_threats.get("brute_force_reason", "Brute-force detected"))
        if rule_threats.get("is_port_scan"):
            rule_points += 15.0
            rule_reasons.append(rule_threats.get("port_scan_reason", "Port scan detected"))
        
        rule_points = min(rule_points, 20.0)
        if rule_points > 0:
            total_score += rule_points
            breakdown["stateful_rule_detectors"] = {
                "points": rule_points,
                "reasons": rule_reasons
            }

        # Factor 4: Target Asset Criticality (Weight: 15%)
        crit = target_device.criticality if target_device else "MEDIUM"
        asset_points = self.ASSET_CRITICALITY_SCORES.get(crit.upper(), 10.0)
        if is_malicious or anomaly_score > 0.6 or rule_points > 0:
            total_score += asset_points
            breakdown["target_asset_criticality"] = {
                "points": asset_points,
                "criticality": crit,
                "hostname": target_device.hostname if target_device else "Unknown Host"
            }

        # Factor 5: UEBA Behavioral Deviation
        if ueba_score > 30.0:
            ueba_points = round((ueba_score / 100.0) * 15.0, 2)
            total_score += ueba_points
            breakdown["ueba_deviation"] = {
                "points": ueba_points,
                "score": ueba_score
            }

        # Final clamping between 0 and 100
        final_risk = min(round(total_score, 1), 100.0)

        # Severity Mapping (FR-18)
        if final_risk >= 90.0:
            severity = "CRITICAL"
        elif final_risk >= 70.0:
            severity = "HIGH"
        elif final_risk >= 40.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return final_risk, severity, breakdown

risk_engine = RiskEngine()
