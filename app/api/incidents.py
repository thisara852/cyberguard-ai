from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.core.database import get_db
from app.models.entities import Incident, IncidentTimeline, IncidentEvidence, ResponseAction, User, RoleEnum
from app.schemas.incident import (
    IncidentResponse, IncidentDetailResponse, IncidentStatusUpdate,
    IncidentAssignUpdate, TimelineNoteCreate, ResponseActionRequest, ResponseActionResponse
)
from app.services.auth_service import get_current_user, require_role
from app.services.response_engine import response_engine
from app.services.audit_service import log_action

router = APIRouter(prefix="/incidents", tags=["Incident Management & Response"])

@router.get("/", response_model=List[IncidentResponse])
def get_incidents(
    skip: int = 0,
    limit: int = 50,
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-28: Search and filter historical security incidents."""
    query = db.query(Incident)
    if status_filter:
        query = query.filter(Incident.status == status_filter.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if assigned_to:
        query = query.filter(Incident.assigned_to == assigned_to)
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            (Incident.title.ilike(search_fmt)) |
            (Incident.incident_code.ilike(search_fmt)) |
            (Incident.description.ilike(search_fmt))
        )
    return query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_detail(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-26, FR-27: Retrieve incident details with chronological timeline and evidence."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.put("/{incident_id}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_id: int,
    update_in: IncidentStatusUpdate,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-25: Maintain incident lifecycle statuses (NEW, INVESTIGATING, CONTAINED, RESOLVED, CLOSED)."""
    valid_statuses = ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
    new_status = update_in.status.upper()
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    incident.status = new_status
    incident.updated_at = datetime.utcnow()
    if new_status == "CLOSED":
        incident.closed_at = datetime.utcnow()

    # Append to timeline
    timeline = IncidentTimeline(
        incident_id=incident.id,
        action=f"STATUS_CHANGE_{new_status}",
        performed_by=current_user.username,
        notes=update_in.note or f"Status changed from {old_status} to {new_status}"
    )
    db.add(timeline)
    db.commit()
    db.refresh(incident)

    log_action(
        db,
        username=current_user.username,
        action="INCIDENT_STATUS_CHANGE",
        resource_type="INCIDENT",
        resource_id=incident.incident_code,
        details=f"Status transitioned {old_status} -> {new_status}",
        user_id=current_user.id
    )
    return incident

@router.put("/{incident_id}/assign", response_model=IncidentResponse)
def assign_incident(
    incident_id: int,
    assign_in: IncidentAssignUpdate,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-24: Assign incidents to authorized security analysts."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.assigned_to = assign_in.assigned_to
    incident.updated_at = datetime.utcnow()

    timeline = IncidentTimeline(
        incident_id=incident.id,
        action="ASSIGNED",
        performed_by=current_user.username,
        notes=f"Incident assigned to analyst: {assign_in.assigned_to}"
    )
    db.add(timeline)
    db.commit()
    db.refresh(incident)
    return incident

@router.post("/{incident_id}/timeline")
def add_timeline_note(
    incident_id: int,
    note_in: TimelineNoteCreate,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-26: Add analyst investigation notes and milestones to timeline."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = IncidentTimeline(
        incident_id=incident.id,
        action=note_in.action,
        performed_by=current_user.username,
        notes=note_in.notes
    )
    db.add(timeline)
    db.commit()
    return {"message": "Timeline entry added"}

@router.post("/{incident_id}/respond", response_model=ResponseActionResponse)
def trigger_incident_response(
    incident_id: int,
    action_in: ResponseActionRequest,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-40, FR-41: Execute simulated response action for an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        response_rec = response_engine.execute_response(
            db=db,
            action_type=action_in.action_type,
            target_entity=action_in.target_entity,
            executed_by=current_user.username,
            incident_id=incident.id,
            reason=action_in.reason or action_in.notes
        )
        return response_rec
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/responses/history", response_model=List[ResponseActionResponse])
def get_response_history(
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """List all executed response playbooks and containment actions."""
    return db.query(ResponseAction).order_by(ResponseAction.created_at.desc()).all()
