from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.core.database import get_db
from app.models.entities import MLModelRecord, User, RoleEnum, SecurityEvent
from app.schemas.prediction import PredictionRequest, PredictionResponse, ModelMetadataResponse
from app.services.ml_intrusion import intrusion_engine
from app.services.ml_anomaly import anomaly_engine
from app.services.ml_phishing import phishing_detector
from app.services.ml_malware import malware_classifier
from app.services.stateful_detectors import brute_force_detector, port_scan_detector
from app.services.risk_engine import risk_engine
from app.services.alert_dispatcher import alert_dispatcher
from app.services.auth_service import get_current_user, require_role
from app.services.audit_service import log_action

router = APIRouter(prefix="/ml", tags=["Machine Learning & Detection Engines"])

@router.post("/predict-intrusion", response_model=PredictionResponse)
def predict_intrusion(
    req: PredictionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-10, FR-16, FR-17: Comprehensive threat detection pipeline combining Supervised ML, Isolation Forest & Risk Engine."""
    event_dict = req.dict()

    # 1. Supervised Intrusion Classification
    ml_res = intrusion_engine.predict(event_dict)

    # 2. Unsupervised Anomaly Scoring
    anomaly_score = anomaly_engine.score_event(event_dict)

    # 3. Stateful Rule Checks
    rule_threats = {}
    if req.destination_port == 22 and req.flags == "FIN":
        is_bf, count, reason = brute_force_detector.record_failure(req.source_ip)
        rule_threats["is_brute_force"] = is_bf
        rule_threats["brute_force_reason"] = reason

    is_scan, pcount, scan_reason = port_scan_detector.record_connection(req.source_ip, req.destination_port)
    rule_threats["is_port_scan"] = is_scan
    rule_threats["port_scan_reason"] = scan_reason

    # 4. Composite Risk Calculation (FR-17, FR-18, FR-31)
    risk_score, severity, explanation = risk_engine.compute_risk(
        ml_prediction=ml_res,
        anomaly_score=anomaly_score,
        rule_threats=rule_threats
    )

    # 5. Alert Dispatch if Risk Threshold exceeded (FR-19, FR-20)
    if risk_score >= 40.0 or ml_res["is_malicious"]:
        alert_dispatcher.process_and_dispatch(
            db=db,
            source_ip=req.source_ip,
            target_ip=req.destination_ip,
            threat_type=ml_res["threat_type"] if ml_res["is_malicious"] else "Network Anomaly",
            severity=severity,
            risk_score=risk_score,
            description=f"Automated detection: {ml_res['threat_type']} with risk score {risk_score}",
            explanation=explanation
        )

    return {
        "model_name": ml_res["model_name"],
        "model_version": ml_res["model_version"],
        "is_malicious": ml_res["is_malicious"],
        "threat_type": ml_res["threat_type"],
        "confidence": ml_res["confidence"],
        "anomaly_score": anomaly_score,
        "risk_score": risk_score,
        "severity": severity,
        "explanation": explanation
    }

@router.post("/scan-url")
def scan_phishing_url(
    url: str = Query(..., description="URL to evaluate for phishing risk"),
    current_user: User = Depends(get_current_user)
):
    """FR-14: Phishing URL analysis and risk classification."""
    return phishing_detector.analyze_url(url)

@router.post("/scan-file")
def scan_file_metadata(
    filename: str,
    file_size: int = 1024,
    md5_hash: str = "",
    section_entropy: float = 5.0,
    imports: Optional[str] = "",
    current_user: User = Depends(get_current_user)
):
    """FR-15: Malware file metadata analysis and signature inspection."""
    import_list = [i.strip() for i in imports.split(",") if i.strip()] if imports else []
    return malware_classifier.analyze_metadata(
        filename=filename,
        file_size=file_size,
        md5_hash=md5_hash,
        section_entropy=section_entropy,
        imports=import_list
    )

@router.get("/models")
def get_ml_models(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-44, FR-45: View registered ML models, versions, and evaluation metrics."""
    models = db.query(MLModelRecord).order_by(MLModelRecord.registered_at.desc()).all()
    res = []
    for m in models:
        res.append({
            "id": m.id,
            "model_name": m.model_name,
            "version": m.version,
            "algorithm": m.algorithm,
            "accuracy": m.accuracy,
            "precision": m.precision,
            "recall": m.recall,
            "f1_score": m.f1_score,
            "is_production": m.is_production,
            "registered_at": m.registered_at
        })
    return res

@router.post("/train")
def train_intrusion_model(
    samples: int = Query(1500, ge=500, le=5000),
    current_user: User = Depends(require_role([RoleEnum.SUPER_ADMIN])),
    db: Session = Depends(get_db)
):
    """FR-44, FR-50: Train / retrain intrusion detection machine learning model."""
    metrics = intrusion_engine.train_model(db=db, sample_count=samples)
    log_action(
        db,
        username=current_user.username,
        action="MODEL_TRAINING",
        resource_type="ML_MODEL",
        resource_id=intrusion_engine.model_name,
        details=f"Trained model on {samples} samples. F1 Score: {metrics.get('f1_score')}",
        user_id=current_user.id
    )
    return {
        "message": "Model successfully trained and deployed to production",
        "model_name": intrusion_engine.model_name,
        "metrics": metrics
    }
