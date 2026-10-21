from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.core.database import get_db
from app.models.entities import Alert, User, RoleEnum, Incident, IncidentTimeline
from app.schemas.alert import AlertResponse
from app.services.auth_service import get_current_user, require_role
from app.services.audit_service import log_action

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])

@router.get("/", response_model=List[AlertResponse])
def get_alerts(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    source_ip: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-21: Multi-criteria alert filtering and pagination."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status_filter:
        query = query.filter(Alert.status == status_filter.upper())
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()

@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-22: Acknowledge an alert to mark analyst assignment."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = current_user.username
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)

    log_action(
        db,
        username=current_user.username,
        action="ALERT_ACKNOWLEDGED",
        resource_type="ALERT",
        resource_id=str(alert.id),
        details=f"Alert {alert.id} acknowledged by {current_user.username}",
        user_id=current_user.id
    )
    return alert

@router.post("/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(
    alert_id: int,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """Mark an alert as resolved."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "RESOLVED"
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert

@router.post("/{alert_id}/escalate")
def escalate_alert_to_incident(
    alert_id: int,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-23: Convert an active alert into a formal security incident."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Generate incident code
    inc_count = db.query(Incident).count() + 1
    code = f"INC-{datetime.utcnow().year}-{inc_count:04d}"

    incident = Incident(
        incident_code=code,
        title=f"Incident: {alert.title}",
        description=alert.description or f"Escalated from Alert #{alert.id} ({alert.threat_type})",
        severity=alert.severity,
        status="NEW",
        assigned_to=current_user.username,
        risk_score=alert.risk_score,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.add(incident)
    db.flush()

    # Add initial timeline event (FR-26)
    timeline = IncidentTimeline(
        incident_id=incident.id,
        action="INCIDENT_CREATED",
        performed_by=current_user.username,
        notes=f"Escalated from Alert #{alert.id} (Source: {alert.source_ip}, Target: {alert.target_ip})"
    )
    db.add(timeline)

    # Update alert status
    alert.status = "ESCALATED"
    alert.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(incident)

    log_action(
        db,
        username=current_user.username,
        action="ALERT_ESCALATION",
        resource_type="INCIDENT",
        resource_id=incident.incident_code,
        details=f"Escalated alert #{alert.id} to incident {incident.incident_code}",
        user_id=current_user.id
    )

    return {
        "message": f"Alert escalated to incident {incident.incident_code}",
        "incident_id": incident.id,
        "incident_code": incident.incident_code
    }
