from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class TimelineItemResponse(BaseModel):
    id: int
    action: str
    performed_by: str
    notes: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True

class EvidenceResponse(BaseModel):
    id: int
    evidence_type: str
    data: str
    captured_at: datetime

    class Config:
        from_attributes = True

class IncidentResponse(BaseModel):
    id: int
    incident_code: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    assigned_to: Optional[str] = None
    risk_score: float
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class IncidentDetailResponse(IncidentResponse):
    timeline: List[TimelineItemResponse] = []
    evidence: List[EvidenceResponse] = []

class IncidentStatusUpdate(BaseModel):
    status: str # NEW, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    note: Optional[str] = None

class IncidentAssignUpdate(BaseModel):
    assigned_to: str

class TimelineNoteCreate(BaseModel):
    action: str
    notes: str

class ResponseActionRequest(BaseModel):
    action_type: str # BLOCK_IP, DISABLE_USER, ISOLATE_DEVICE, QUARANTINE_FILE
    target_entity: str
    reason: Optional[str] = None
    notes: Optional[str] = None

class ResponseActionResponse(BaseModel):
    id: int
    incident_id: Optional[int] = None
    action_type: str
    target_entity: str
    status: str
    executed_by: str
    reason: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
