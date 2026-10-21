from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
)
from sqlalchemy.orm import relationship
from app.core.database import Base

class RoleEnum:
    SUPER_ADMIN = "Super Admin"
    SECURITY_ANALYST = "Security Analyst"
    NORMAL_USER = "Normal User"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=True)
    role = Column(String(32), default=RoleEnum.NORMAL_USER, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(64), nullable=False)
    action = Column(String(64), index=True, nullable=False)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), default="127.0.0.1")

class MonitoredDevice(Base):
    __tablename__ = "monitored_devices"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(128), index=True, nullable=False)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    mac_address = Column(String(32), nullable=True)
    os_type = Column(String(64), default="Linux Server")
    criticality = Column(String(16), default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(16), default="ONLINE")        # ONLINE, OFFLINE, ISOLATED
    risk_score = Column(Float, default=0.0)
    last_seen = Column(DateTime, default=datetime.utcnow)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True, nullable=False)
    destination_ip = Column(String(45), index=True, nullable=False)
    source_port = Column(Integer, default=0)
    destination_port = Column(Integer, default=80)
    protocol = Column(String(16), default="TCP")
    service = Column(String(32), default="http")
    duration = Column(Float, default=0.1)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    packet_count = Column(Integer, default=1)
    flags = Column(String(16), default="SYN")
    event_category = Column(String(32), default="NETWORK")  # NETWORK, AUTH, ENDPOINT, WEB
    raw_payload = Column(Text, nullable=True)
    is_processed = Column(Boolean, default=False)

class PredictionRecord(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True)
    model_name = Column(String(64), nullable=False)
    model_version = Column(String(32), default="1.0.0")
    is_malicious = Column(Boolean, default=False)
    threat_type = Column(String(64), default="Normal")
    confidence = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    severity = Column(String(16), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    threat_type = Column(String(64), default="Intrusion")
    severity = Column(String(16), default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=75.0)
    source_ip = Column(String(45), index=True, nullable=False)
    target_ip = Column(String(45), index=True, nullable=False)
    status = Column(String(16), default="OPEN")    # OPEN, ACKNOWLEDGED, RESOLVED, ESCALATED
    dedup_hash = Column(String(64), index=True)
    event_id = Column(Integer, nullable=True)
    acknowledged_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_code = Column(String(32), unique=True, index=True, nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), default="HIGH")
    status = Column(String(16), default="NEW")  # NEW, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    assigned_to = Column(String(64), nullable=True)
    risk_score = Column(Float, default=80.0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)

    timeline = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    evidence = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")

class IncidentTimeline(Base):
    __tablename__ = "incident_timelines"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    action = Column(String(128), nullable=False)
    performed_by = Column(String(64), default="System")
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="timeline")

class IncidentEvidence(Base):
    __tablename__ = "incident_evidences"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    evidence_type = Column(String(32), default="LOG")
    data = Column(Text, nullable=False)
    captured_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="evidence")

class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=True)
    action_type = Column(String(32), nullable=False) # BLOCK_IP, DISABLE_USER, ISOLATE_DEVICE, QUARANTINE_FILE
    target_entity = Column(String(128), nullable=False)
    status = Column(String(16), default="SIMULATED")  # SIMULATED, APPLIED, REVERTED
    executed_by = Column(String(64), default="Security Analyst")
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class MLModelRecord(Base):
    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(64), nullable=False)
    version = Column(String(32), nullable=False)
    algorithm = Column(String(64), nullable=False)
    accuracy = Column(Float, default=0.0)
    precision = Column(Float, default=0.0)
    recall = Column(Float, default=0.0)
    f1_score = Column(Float, default=0.0)
    is_production = Column(Boolean, default=False)
    artifact_path = Column(String(256), nullable=True)
    metrics_json = Column(Text, nullable=True)
    registered_at = Column(DateTime, default=datetime.utcnow)

class ModelMonitoringLog(Base):
    __tablename__ = "model_monitoring_logs"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(64), nullable=False)
    model_version = Column(String(32), default="1.0.0")
    latency_ms = Column(Float, default=0.0)
    drift_score = Column(Float, default=0.0)
    status = Column(String(32), default="HEALTHY") # HEALTHY, WARNING, DRIFT_DETECTED
    timestamp = Column(DateTime, default=datetime.utcnow)

class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String(64), primary_key=True, index=True)
    value = Column(String(256), nullable=False)
    category = Column(String(32), default="DETECTION")
    description = Column(String(256), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
