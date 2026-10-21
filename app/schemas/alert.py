from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AlertResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    threat_type: str
    severity: str
    risk_score: float
    source_ip: str
    target_ip: str
    status: str
    acknowledged_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class AlertStatusUpdate(BaseModel):
    status: str # OPEN, ACKNOWLEDGED, RESOLVED, ESCALATED
