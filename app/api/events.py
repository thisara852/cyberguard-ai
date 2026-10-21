from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.core.database import get_db
from app.models.entities import SecurityEvent, User, RoleEnum
from app.schemas.event import (
    SecurityEventCreate, SecurityEventResponse, SecurityEventBatch, IngestionSummary
)
from app.services.event_ingestion import ingest_single_event, ingest_event_batch, ingest_csv_content
from app.services.synthetic_data_generator import generate_synthetic_events
from app.services.auth_service import get_current_user, require_role

router = APIRouter(prefix="/events", tags=["Security Data Collection & Events"])

@router.post("/ingest", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
def ingest_event(
    event_in: SecurityEventCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-06, FR-07: Ingest and normalize a single incoming security event."""
    return ingest_single_event(db, event_in)

@router.post("/batch", response_model=IngestionSummary)
def ingest_batch(
    batch_in: SecurityEventBatch,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-06, FR-07: Ingest a batch of events with validation summary."""
    records = [ev.dict() for ev in batch_in.events]
    return ingest_event_batch(db, records)

@router.post("/upload-csv", response_model=IngestionSummary)
async def upload_csv_dataset(
    file: UploadFile = File(...),
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-06: Upload and parse cybersecurity log files/datasets in CSV format."""
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="File must be a CSV format dataset")
    content = (await file.read()).decode("utf-8", errors="ignore")
    return ingest_csv_content(db, content)

@router.get("/", response_model=List[SecurityEventResponse])
def get_events(
    skip: int = 0,
    limit: int = 100,
    source_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Query normalized security events with multi-criteria filtering (FR-21)."""
    query = db.query(SecurityEvent)
    if source_ip:
        query = query.filter(SecurityEvent.source_ip == source_ip)
    if protocol:
        query = query.filter(SecurityEvent.protocol == protocol.upper())
    if category:
        query = query.filter(SecurityEvent.event_category == category.upper())
    return query.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()

@router.post("/generate-sample", response_model=IngestionSummary)
def generate_sample_events(
    count: int = Query(50, ge=10, le=500),
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """Generate and ingest realistic synthetic events for instant system demonstration."""
    sample_records = generate_synthetic_events(count)
    return ingest_event_batch(db, sample_records)
