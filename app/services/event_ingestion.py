import csv
import io
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from pydantic import ValidationError

from app.models.entities import SecurityEvent
from app.schemas.event import SecurityEventCreate, IngestionSummary

def normalize_and_validate_record(raw: Dict[str, Any]) -> Tuple[Optional[SecurityEventCreate], Optional[str]]:
    """Validate and normalize a raw dictionary into a SecurityEventCreate model."""
    try:
        # Standardize field names
        mapping = {
            "src_ip": "source_ip",
            "dst_ip": "destination_ip",
            "src_port": "source_port",
            "dst_port": "destination_port",
            "proto": "protocol"
        }
        cleaned = {}
        for k, v in raw.items():
            key = mapping.get(k.strip().lower(), k.strip().lower())
            val = v.strip() if isinstance(v, str) else v
            cleaned[key] = val

        # Handle numeric casts
        if "source_port" in cleaned and cleaned["source_port"]:
            cleaned["source_port"] = int(float(cleaned["source_port"]))
        if "destination_port" in cleaned and cleaned["destination_port"]:
            cleaned["destination_port"] = int(float(cleaned["destination_port"]))
        if "duration" in cleaned and cleaned["duration"]:
            cleaned["duration"] = float(cleaned["duration"])
        if "bytes_sent" in cleaned and cleaned["bytes_sent"]:
            cleaned["bytes_sent"] = int(float(cleaned["bytes_sent"]))
        if "bytes_received" in cleaned and cleaned["bytes_received"]:
            cleaned["bytes_received"] = int(float(cleaned["bytes_received"]))
        if "packet_count" in cleaned and cleaned["packet_count"]:
            cleaned["packet_count"] = int(float(cleaned["packet_count"]))

        # Handle timestamp parsing if present
        if "timestamp" in cleaned and isinstance(cleaned["timestamp"], str) and cleaned["timestamp"]:
            try:
                cleaned["timestamp"] = datetime.fromisoformat(cleaned["timestamp"].replace("Z", "+00:00"))
            except Exception:
                cleaned["timestamp"] = datetime.utcnow()
        else:
            cleaned["timestamp"] = datetime.utcnow()

        event = SecurityEventCreate(**cleaned)
        return event, None
    except (ValidationError, ValueError, TypeError) as e:
        return None, str(e)

def ingest_single_event(db: Session, event_data: SecurityEventCreate) -> SecurityEvent:
    """Persist a single validated security event to the database (FR-06, FR-07)."""
    db_event = SecurityEvent(
        timestamp=event_data.timestamp or datetime.utcnow(),
        source_ip=event_data.source_ip,
        destination_ip=event_data.destination_ip,
        source_port=event_data.source_port,
        destination_port=event_data.destination_port,
        protocol=event_data.protocol,
        service=event_data.service,
        duration=event_data.duration,
        bytes_sent=event_data.bytes_sent,
        bytes_received=event_data.bytes_received,
        packet_count=event_data.packet_count,
        flags=event_data.flags,
        event_category=event_data.event_category,
        raw_payload=event_data.raw_payload,
        is_processed=False
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event

def ingest_event_batch(db: Session, raw_records: List[Dict[str, Any]]) -> IngestionSummary:
    """Batch ingestion with validation and error reporting (FR-07, FR-08)."""
    accepted = 0
    rejected = 0
    errors = []
    events_to_add = []

    for idx, record in enumerate(raw_records):
        event_create, err = normalize_and_validate_record(record)
        if err:
            rejected += 1
            if len(errors) < 20: # Cap error log size
                errors.append(f"Row {idx + 1}: {err}")
            continue

        db_event = SecurityEvent(
            timestamp=event_create.timestamp or datetime.utcnow(),
            source_ip=event_create.source_ip,
            destination_ip=event_create.destination_ip,
            source_port=event_create.source_port,
            destination_port=event_create.destination_port,
            protocol=event_create.protocol,
            service=event_create.service,
            duration=event_create.duration,
            bytes_sent=event_create.bytes_sent,
            bytes_received=event_create.bytes_received,
            packet_count=event_create.packet_count,
            flags=event_create.flags,
            event_category=event_create.event_category,
            raw_payload=event_create.raw_payload,
            is_processed=False
        )
        events_to_add.append(db_event)
        accepted += 1

    if events_to_add:
        db.bulk_save_objects(events_to_add)
        db.commit()

    return IngestionSummary(
        total_received=len(raw_records),
        accepted=accepted,
        rejected=rejected,
        errors=errors
    )

def ingest_csv_content(db: Session, csv_text: str) -> IngestionSummary:
    """Parse CSV text stream and perform batch ingestion (FR-06)."""
    reader = csv.DictReader(io.StringIO(csv_text))
    records = [row for row in reader]
    return ingest_event_batch(db, records)
