from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime

class PredictionRequest(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: int = 0
    destination_port: int = 80
    protocol: str = "TCP"
    service: str = "http"
    duration: float = 0.1
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_count: int = 1
    flags: str = "SYN"

class PredictionResponse(BaseModel):
    model_name: str
    model_version: str
    is_malicious: bool
    threat_type: str
    confidence: float
    anomaly_score: float
    risk_score: float
    severity: str
    explanation: Dict[str, Any]

class ModelMetadataResponse(BaseModel):
    id: int
    model_name: str
    version: str
    algorithm: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    is_production: bool
    registered_at: datetime
    metrics: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
