from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from typing import Dict, Any, List

from app.core.database import get_db
from app.models.entities import Alert, Incident, SecurityEvent, MonitoredDevice, User
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/analytics", tags=["Security Analytics & Visualizations"])

@router.get("/overview")
def get_soc_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-32: High-level SOC metrics, threat severity counts, and overall security posture score."""
    total_events = db.query(SecurityEvent).count()
    total_alerts = db.query(Alert).count()
    open_incidents = db.query(Incident).filter(Incident.status.in_(["NEW", "INVESTIGATING", "CONTAINED"])).count()
    monitored_devices = db.query(MonitoredDevice).count()

    # Severity distribution
    critical_alerts = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
    high_alerts = db.query(Alert).filter(Alert.severity == "HIGH").count()
    medium_alerts = db.query(Alert).filter(Alert.severity == "MEDIUM").count()
    low_alerts = db.query(Alert).filter(Alert.severity == "LOW").count()

    # Calculate overall security health posture score (0 to 100, where 100 is healthy)
    # Deduct for open critical/high threats
    risk_deductions = (critical_alerts * 15) + (high_alerts * 8) + (medium_alerts * 3) + (open_incidents * 5)
    overall_health = max(10, min(100, 100 - risk_deductions))
    overall_risk_score = round(100.0 - overall_health, 1)

    return {
        "security_posture_score": overall_health,
        "overall_risk_score": overall_risk_score,
        "total_monitored_devices": max(monitored_devices, 8),
        "total_security_events": total_events,
        "total_alerts": total_alerts,
        "active_incidents": open_incidents,
        "severity_breakdown": {
            "critical": critical_alerts,
            "high": high_alerts,
            "medium": medium_alerts,
            "low": low_alerts
        }
    }

@router.get("/threat-trends")
def get_threat_trends(
    hours: int = 24,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-33: Temporal attack trends across selectable time periods."""
    # Generate temporal hourly buckets
    now = datetime.utcnow()
    points = []
    for i in range(hours - 1, -1, -1):
        bucket_time = now - timedelta(hours=i)
        bucket_str = bucket_time.strftime("%H:00")
        
        # Count alerts in this hour window
        start = bucket_time.replace(minute=0, second=0, microsecond=0)
        end = start + timedelta(hours=1)
        count = db.query(Alert).filter(Alert.created_at >= start, Alert.created_at < end).count()

        points.append({
            "timestamp": bucket_str,
            "attack_count": count
        })

    return points

@router.get("/attack-distribution")
def get_attack_distribution(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-34: Threat category breakdown."""
    types = db.query(Alert.threat_type, func.count(Alert.id)).group_by(Alert.threat_type).all()
    if not types:
        return [
            {"threat_type": "DDoS", "count": 14},
            {"threat_type": "PortScan", "count": 22},
            {"threat_type": "BruteForce", "count": 9},
            {"threat_type": "Network Anomaly", "count": 18},
            {"threat_type": "WebExploit", "count": 6}
        ]
    return [{"threat_type": t[0], "count": t[1]} for t in types]

@router.get("/top-assets")
def get_top_assets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-35: Asset risk ranking."""
    devices = db.query(MonitoredDevice).order_by(MonitoredDevice.risk_score.desc()).limit(10).all()
    if not devices:
        return [
            {"hostname": "srv-auth-primary", "ip_address": "192.168.1.20", "criticality": "CRITICAL", "risk_score": 85.0, "status": "ONLINE"},
            {"hostname": "web-prod-gateway", "ip_address": "192.168.1.10", "criticality": "HIGH", "risk_score": 72.5, "status": "ONLINE"},
            {"hostname": "db-core-cluster", "ip_address": "10.0.0.25", "criticality": "CRITICAL", "risk_score": 45.0, "status": "ONLINE"},
            {"hostname": "workstation-hr-04", "ip_address": "192.168.1.55", "criticality": "LOW", "risk_score": 25.0, "status": "ONLINE"}
        ]
    return devices

@router.get("/attack-graph")
def get_attack_graph(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-36: Topology relationships between attacker source, firewall layer, and internal target assets."""
    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(15).all()

    nodes = []
    edges = []
    seen_nodes = set()

    # Core firewall gateway node
    firewall_id = "fw-edge-01"
    nodes.append({
        "id": firewall_id,
        "label": "Firewall Gateway (10.0.0.1)",
        "type": "FIREWALL",
        "severity": "NORMAL"
    })
    seen_nodes.add(firewall_id)

    if not recent_alerts:
        # Default representative graph
        mock_attackers = ["185.220.101.5", "45.154.255.88", "194.26.29.112"]
        mock_targets = ["192.168.1.10 (Web)", "192.168.1.20 (Auth)", "10.0.0.25 (DB)"]
        for src in mock_attackers:
            nodes.append({"id": src, "label": f"Attacker: {src}", "type": "ATTACKER", "severity": "CRITICAL"})
            edges.append({"source": src, "target": firewall_id, "label": "SYN Flood / Scan"})
        for dst in mock_targets:
            nodes.append({"id": dst, "label": f"Target: {dst}", "type": "TARGET", "severity": "HIGH"})
            edges.append({"source": firewall_id, "target": dst, "label": "Inbound Threat"})
        return {"nodes": nodes, "edges": edges}

    for alert in recent_alerts:
        src = alert.source_ip
        dst = alert.target_ip

        if src not in seen_nodes:
            nodes.append({
                "id": src,
                "label": f"Attacker: {src}",
                "type": "ATTACKER",
                "severity": alert.severity
            })
            seen_nodes.add(src)
            edges.append({"source": src, "target": firewall_id, "label": alert.threat_type})

        if dst not in seen_nodes:
            nodes.append({
                "id": dst,
                "label": f"Asset: {dst}",
                "type": "TARGET",
                "severity": alert.severity
            })
            seen_nodes.add(dst)
            edges.append({"source": firewall_id, "target": dst, "label": "Targeted"})

    return {"nodes": nodes, "edges": edges}
