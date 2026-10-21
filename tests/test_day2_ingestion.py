from app.core.database import SessionLocal, Base, engine
from app.models.entities import SecurityEvent
from app.schemas.event import SecurityEventCreate
from app.services.event_ingestion import (
    ingest_single_event, ingest_event_batch, ingest_csv_content, normalize_and_validate_record
)
from app.services.synthetic_data_generator import generate_synthetic_events

def setup_module(module):
    Base.metadata.create_all(bind=engine)

def test_normalize_valid_record():
    raw = {
        "src_ip": "192.168.1.55",
        "dst_ip": "10.0.0.1",
        "src_port": "44321",
        "dst_port": "80",
        "proto": "tcp",
        "service": "HTTP",
        "duration": "0.45",
        "bytes_sent": "1200",
        "bytes_received": "3500",
        "packet_count": "10",
        "flags": "ACK"
    }
    model, err = normalize_and_validate_record(raw)
    assert err is None
    assert model.source_ip == "192.168.1.55"
    assert model.protocol == "TCP"
    assert model.service == "http"
    assert model.bytes_sent == 1200

def test_reject_invalid_ip():
    raw = {
        "src_ip": "not_an_ip_address",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP"
    }
    model, err = normalize_and_validate_record(raw)
    assert model is None
    assert err is not None
    assert "Invalid IP address format" in err

def test_single_and_batch_ingestion():
    db = SessionLocal()
    event_in = SecurityEventCreate(
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        source_port=50000,
        destination_port=443,
        protocol="TCP",
        service="https",
        bytes_sent=500,
        bytes_received=2000
    )
    event = ingest_single_event(db, event_in)
    assert event.id is not None
    assert event.source_ip == "192.168.1.100"

    # Test synthetic generation and batch ingestion
    synthetic_records = generate_synthetic_events(20)
    summary = ingest_event_batch(db, synthetic_records)
    assert summary.accepted == 20
    assert summary.rejected == 0
    db.close()

def test_csv_ingestion():
    db = SessionLocal()
    csv_data = """source_ip,destination_ip,source_port,destination_port,protocol,service,bytes_sent,bytes_received
192.168.1.101,10.0.0.1,50001,80,TCP,http,300,1500
192.168.1.102,10.0.0.2,50002,443,TCP,https,400,2500
"""
    summary = ingest_csv_content(db, csv_data)
    assert summary.accepted == 2
    db.close()

if __name__ == "__main__":
    setup_module(None)
    test_normalize_valid_record()
    print("✓ Normalization test passed")
    test_reject_invalid_ip()
    print("✓ Validation & rejection test passed")
    test_single_and_batch_ingestion()
    print("✓ Ingestion & batch test passed")
    test_csv_ingestion()
    print("✓ CSV ingestion test passed")
    print("All Day 2 tests passed successfully!")
