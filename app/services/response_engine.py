from sqlalchemy.orm import Session
from datetime import datetime
from typing import Dict, Any, Optional

from app.models.entities import ResponseAction, Incident, IncidentTimeline, MonitoredDevice, User
from app.services.audit_service import log_action

class ResponseEngine:
    """Automated and Simulated Incident Response Playbooks (FR-40, FR-41)."""

    VALID_ACTIONS = ["BLOCK_IP", "DISABLE_USER", "ISOLATE_DEVICE", "QUARANTINE_FILE"]

    def execute_response(
        self,
        db: Session,
        action_type: str,
        target_entity: str,
        executed_by: str,
        incident_id: Optional[int] = None,
        reason: Optional[str] = None
    ) -> ResponseAction:
        """Safely execute a simulated cybersecurity countermeasure."""
        action_upper = action_type.upper()
        if action_upper not in self.VALID_ACTIONS:
            raise ValueError(f"Invalid response action: {action_type}")

        simulated_details = ""

        # 1. Simulate IP Block
        if action_upper == "BLOCK_IP":
            simulated_details = f"[Simulated Firewall Rule] Applied DROP rule on Edge Gateway for Source IP: {target_entity}"

        # 2. Simulate User Account Lockout
        elif action_upper == "DISABLE_USER":
            user = db.query(User).filter(User.username == target_entity).first()
            if user:
                user.is_active = False
            simulated_details = f"[Simulated Identity Provider] Disabled user account: {target_entity}"

        # 3. Simulate Host/Device Network Isolation
        elif action_upper == "ISOLATE_DEVICE":
            device = db.query(MonitoredDevice).filter(
                (MonitoredDevice.ip_address == target_entity) | (MonitoredDevice.hostname == target_entity)
            ).first()
            if device:
                device.status = "ISOLATED"
            simulated_details = f"[Simulated Network Switch] Moved device {target_entity} to quarantine isolation VLAN"

        # 4. Simulate File Quarantine
        elif action_upper == "QUARANTINE_FILE":
            simulated_details = f"[Simulated Endpoint EDR] Vaulted file/hash {target_entity} into encrypted sandbox storage"

        # Record response action
        action_record = ResponseAction(
            incident_id=incident_id,
            action_type=action_upper,
            target_entity=target_entity,
            status="APPLIED",
            executed_by=executed_by,
            reason=reason or simulated_details,
            created_at=datetime.utcnow()
        )
        db.add(action_record)

        # Update Incident timeline if associated with an incident
        if incident_id:
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
            if incident:
                timeline_entry = IncidentTimeline(
                    incident_id=incident.id,
                    action=f"RESPONSE_{action_upper}",
                    performed_by=executed_by,
                    notes=f"{simulated_details}. Reason: {reason or 'Immediate containment'}"
                )
                db.add(timeline_entry)
                incident.updated_at = datetime.utcnow()
                if incident.status == "NEW":
                    incident.status = "CONTAINED"

        db.commit()
        db.refresh(action_record)

        # Compliance audit logging (FR-41, FR-42)
        log_action(
            db,
            username=executed_by,
            action=f"SIMULATED_RESPONSE_{action_upper}",
            resource_type="RESPONSE",
            resource_id=str(action_record.id),
            details=simulated_details
        )

        return action_record

response_engine = ResponseEngine()
