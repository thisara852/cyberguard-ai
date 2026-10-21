from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.core.database import get_db
from app.models.entities import MLModelRecord, User, RoleEnum
from app.services.auth_service import require_role, get_current_user
from app.services.mlops_service import mlops_engine
from app.services.audit_service import log_action

router = APIRouter(prefix="/mlops", tags=["MLOps & Model Governance"])

@router.get("/health")
def get_mlops_health(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-48, FR-49: Retrieve real-time model health, latency, and data drift metrics."""
    return mlops_engine.get_model_health_report(db)

@router.post("/promote/{model_id}")
def promote_model_to_production(
    model_id: int,
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN])),
    db: Session = Depends(get_db)
):
    """FR-51: Promote an evaluated candidate model to active production status."""
    target_model = db.query(MLModelRecord).filter(MLModelRecord.id == model_id).first()
    if not target_model:
        raise HTTPException(status_code=404, detail="Model record not found")

    # Demote previous production versions for this model name
    db.query(MLModelRecord).filter(
        MLModelRecord.model_name == target_model.model_name
    ).update({"is_production": False})

    target_model.is_production = True
    db.commit()

    log_action(
        db,
        username=current_user.username,
        action="MODEL_PROMOTION",
        resource_type="ML_MODEL",
        resource_id=str(target_model.id),
        details=f"Promoted {target_model.model_name} version {target_model.version} to PRODUCTION",
        user_id=current_user.id
    )
    return {"message": f"Model {target_model.model_name} v{target_model.version} promoted to production"}
