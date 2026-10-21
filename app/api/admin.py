from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import json
from datetime import datetime

from app.core.database import get_db
from app.models.entities import User, AuditLog, SystemSetting, RoleEnum
from app.schemas.auth import UserResponse, AuditLogResponse
from app.services.auth_service import require_role, get_current_user
from app.services.audit_service import log_action

router = APIRouter(prefix="/admin", tags=["Administration & Audit"])

@router.get("/users", response_model=List[UserResponse])
def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """List registered users."""
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@router.put("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role: str = Query(..., pattern="^(Super Admin|Security Analyst|Normal User)$"),
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN])),
    db: Session = Depends(get_db)
):
    """FR-03: Assign role to user (Restricted to Super Admin)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    old_role = user.role
    user.role = role
    db.commit()
    db.refresh(user)

    log_action(
        db,
        username=current_user.username,
        action="USER_ROLE_CHANGE",
        resource_type="USER",
        resource_id=str(user.id),
        details=f"Changed role of {user.username} from {old_role} to {role}",
        user_id=current_user.id
    )
    return user

@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action: Optional[str] = None,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-42: View chronological audit logs for security traceability."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs

@router.get("/settings")
def get_system_settings(
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST])),
    db: Session = Depends(get_db)
):
    """FR-55: Retrieve active system detection thresholds and configuration."""
    settings_records = db.query(SystemSetting).all()
    return {s.key: {"value": s.value, "category": s.category, "description": s.description} for s in settings_records}

@router.put("/settings/{key}")
def update_system_setting(
    key: str,
    value: str,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN])),
    db: Session = Depends(get_db)
):
    """FR-55: Configure system threshold settings."""
    setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if not setting:
        setting = SystemSetting(key=key, value=value, category="SYSTEM", description=f"Custom setting {key}")
        db.add(setting)
    else:
        setting.value = value
        setting.updated_at = datetime.utcnow()
    
    db.commit()

    log_action(
        db,
        username=current_user.username,
        action="CONFIG_UPDATE",
        resource_type="SETTING",
        resource_id=key,
        details=f"Updated setting {key} to {value}",
        user_id=current_user.id
    )
    return {"message": f"Setting {key} updated to {value}"}

@router.get("/backup")
def export_backup_summary(
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN])),
    db: Session = Depends(get_db)
):
    """FR-54: Trigger administrator backup metadata snapshot."""
    user_count = db.query(User).count()
    audit_count = db.query(AuditLog).count()
    
    log_action(
        db,
        username=current_user.username,
        action="SYSTEM_BACKUP",
        resource_type="SYSTEM",
        details="Generated system snapshot",
        user_id=current_user.id
    )
    return {
        "status": "SUCCESS",
        "snapshot_time": datetime.utcnow().isoformat(),
        "database_type": "SQLite / Pluggable PostgreSQL",
        "total_users": user_count,
        "total_audit_records": audit_count,
        "backup_location": "cyberguard.db"
    }
