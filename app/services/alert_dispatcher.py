import hashlib
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.entities import Alert, SecurityEvent
from app.services.websocket_manager import ws_manager

class AlertDispatcher:
    """Alert generation, deduplication, and real-time dispatch (FR-19, FR-20)."""

    def __init__(self, dedup_window_minutes: int = 10):
        self.dedup_window_minutes = dedup_window_minutes

    def _generate_dedup_hash(self, source_ip: str, target_ip: str, threat_type: str) -> str:
        raw = f"{source_ip}:{target_ip}:{threat_type}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def process_and_dispatch(
        self,
        db: Session,
        source_ip: str,
        target_ip: str,
        threat_type: str,
        severity: str,
        risk_score: float,
        description: str,
        event_id: Optional[int] = None,
        explanation: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        """Evaluate threshold, deduplicate, and persist alert (FR-19)."""
        # Threshold check: generate alerts for Medium, High, Critical threats
        if risk_score < 40.0 and severity == "LOW":
            return None

        dedup_hash = self._generate_dedup_hash(source_ip, target_ip, threat_type)
        cutoff = datetime.utcnow() - timedelta(minutes=self.dedup_window_minutes)

        # Check for duplicate recent alert
        existing = db.query(Alert).filter(
            Alert.dedup_hash == dedup_hash,
            Alert.created_at >= cutoff,
            Alert.status != "RESOLVED"
        ).first()

        if existing:
            # Update existing alert timestamp rather than flooding
            existing.updated_at = datetime.utcnow()
            existing.risk_score = max(existing.risk_score, risk_score)
            db.commit()
            return existing

        # Create new Alert
        alert = Alert(
            title=f"Detected {threat_type} from {source_ip}",
            description=description,
            threat_type=threat_type,
            severity=severity,
            risk_score=risk_score,
            source_ip=source_ip,
            target_ip=target_ip,
            status="OPEN",
            dedup_hash=dedup_hash,
            event_id=event_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # Broadcast real-time alert via WebSocket (FR-20)
        try:
            loop = asyncio.get_running_loop()
            if loop and loop.is_running():
                loop.create_task(
                    ws_manager.broadcast({
                        "type": "NEW_ALERT",
                        "alert": {
                            "id": alert.id,
                            "title": alert.title,
                            "threat_type": alert.threat_type,
                            "severity": alert.severity,
                            "risk_score": alert.risk_score,
                            "source_ip": alert.source_ip,
                            "target_ip": alert.target_ip,
                            "created_at": alert.created_at.isoformat()
                        }
                    })
                )
        except RuntimeError:
            pass  # No running event loop (sync / unit test mode)

        return alert

alert_dispatcher = AlertDispatcher()
