from sqlalchemy.orm import Session
from app.models.entities import AuditLog
from typing import Optional
from datetime import datetime

def log_action(
    db: Session,
    username: str,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    user_id: Optional[int] = None
) -> AuditLog:
    """Record an immutable audit log entry for compliance (FR-42)."""
    log_entry = AuditLog(
        timestamp=datetime.utcnow(),
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details=details,
        ip_address=ip_address
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
