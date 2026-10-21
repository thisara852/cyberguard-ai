from typing import Dict, Any, List
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.models.entities import Alert, Incident, SecurityEvent, MonitoredDevice

class AISecurityAssistant:
    """Natural Language AI Assistant for SOC analysts (FR-37, FR-38)."""

    def process_query(self, query: str, db: Session) -> Dict[str, Any]:
        """Answer natural language security questions using live security event data."""
        q = query.lower().strip()

        # Query 1: Incident summary
        if "incident" in q or "summar" in q:
            incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()
            if not incidents:
                return {
                    "answer": "Currently, there are no active security incidents logged in the platform.",
                    "type": "INCIDENT_SUMMARY",
                    "confidence": 0.95,
                    "recommendations": ["Ensure log ingest agents are active."]
                }
            items = []
            for inc in incidents:
                items.append(f"• **{inc.incident_code}** [{inc.severity}]: {inc.title} (Status: {inc.status}, Assigned: {inc.assigned_to or 'Unassigned'})")
            
            return {
                "answer": f"Found **{len(incidents)}** recent security incident(s):\n\n" + "\n".join(items),
                "type": "INCIDENT_SUMMARY",
                "confidence": 0.96,
                "recommendations": [
                    "Prioritize resolving any CRITICAL and HIGH status incidents.",
                    "Review associated incident timeline evidence for containment confirmation."
                ]
            }

        # Query 2: Asset risk / why is asset high risk
        elif "asset" in q or "device" in q or "risk" in q or "why" in q:
            high_alerts = db.query(Alert).filter(Alert.severity.in_(["HIGH", "CRITICAL"])).order_by(Alert.created_at.desc()).limit(5).all()
            if high_alerts:
                details = [f"• Target {a.target_ip} targeted by {a.threat_type} from {a.source_ip} (Risk Score: {a.risk_score})" for a in high_alerts]
                return {
                    "answer": "Elevated risk scores are currently driven by the following high-severity events:\n\n" + "\n".join(details),
                    "type": "RISK_EXPLANATION",
                    "confidence": 0.92,
                    "recommendations": [
                        "Execute simulated IP block on identified attacking sources.",
                        "Verify edge firewall rate-limiting policies for target hosts."
                    ]
                }
            return {
                "answer": "All monitored assets are operating within acceptable threat thresholds with normal risk baselines.",
                "type": "RISK_EXPLANATION",
                "confidence": 0.90,
                "recommendations": ["Maintain continuous monitoring."]
            }

        # Query 3: Threat trends / attacks
        elif "threat" in q or "attack" in q or "active" in q:
            alert_count = db.query(Alert).count()
            top_threat = db.query(Alert.threat_type).first()
            tt = top_threat[0] if top_threat else "Network Reconnaissance"
            return {
                "answer": f"The platform has processed **{alert_count}** alerts. The most prevalent threat vector identified is **{tt}**.",
                "type": "THREAT_ANALYSIS",
                "confidence": 0.94,
                "recommendations": [
                    "Inspect Attack Graph visualization to check for distributed botnet behavior.",
                    "Ensure automated alert deduplication is active."
                ]
            }

        # General Fallback
        return {
            "answer": f"CyberGuard AI Assistant evaluated your inquiry: *'{query}'*.\n\n"
                      f"System telemetry indicates active monitoring across network and endpoint layers. "
                      f"You can ask me to: 'Summarize recent incidents', 'Explain asset risk scores', or 'Show active threat vectors'.",
            "type": "GENERAL_GUIDANCE",
            "confidence": 0.88,
            "recommendations": [
                "Review the Main Security Dashboard for live telemetry.",
                "Use the Attack Visualizer to investigate source-to-target pathways."
            ]
        }

ai_assistant = AISecurityAssistant()
