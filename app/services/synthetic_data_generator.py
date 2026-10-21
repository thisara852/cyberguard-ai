import random
import csv
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any
from app.core.config import settings

def generate_synthetic_events(count: int = 500) -> List[Dict[str, Any]]:
    """Generate realistic cybersecurity events across multiple attack categories."""
    attack_types = ["Normal", "DDoS", "PortScan", "BruteForce", "WebExploit", "Anomaly"]
    weights = [0.60, 0.12, 0.10, 0.08, 0.05, 0.05]

    internal_ips = [f"192.168.1.{i}" for i in range(10, 30)] + ["10.0.0.5", "10.0.0.10", "10.0.0.25"]
    external_attackers = [
        "185.220.101.5", "45.154.255.88", "194.26.29.112", "103.145.13.4",
        "91.240.118.172", "193.32.162.155", "198.51.100.42", "203.0.113.19"
    ]
    benign_externals = [
        "8.8.8.8", "1.1.1.1", "142.250.190.46", "13.107.42.14", "151.101.1.69"
    ]

    events = []
    base_time = datetime.utcnow() - timedelta(hours=6)

    for i in range(count):
        cat = random.choices(attack_types, weights=weights)[0]
        event_time = base_time + timedelta(seconds=i * random.randint(5, 30))

        if cat == "Normal":
            src = random.choice(internal_ips)
            dst = random.choice(benign_externals)
            proto = random.choice(["TCP", "UDP", "TCP"])
            svc = random.choice(["http", "https", "dns"])
            dst_port = 443 if svc == "https" else (80 if svc == "http" else 53)
            src_port = random.randint(30000, 65000)
            duration = round(random.uniform(0.05, 2.5), 3)
            bytes_sent = random.randint(200, 4500)
            bytes_rcvd = random.randint(500, 25000)
            packets = random.randint(3, 30)
            flags = "ACK"
            label = "Normal"

        elif cat == "DDoS":
            src = random.choice(external_attackers)
            dst = "192.168.1.10" # Web server target
            proto = "TCP"
            svc = "http"
            dst_port = 80
            src_port = random.randint(10000, 65000)
            duration = round(random.uniform(0.001, 0.05), 3)
            bytes_sent = random.randint(40, 100)
            bytes_rcvd = 0
            packets = random.randint(1, 2)
            flags = "SYN"
            label = "DDoS"

        elif cat == "PortScan":
            src = random.choice(external_attackers)
            dst = random.choice(internal_ips)
            proto = "TCP"
            dst_port = random.randint(20, 1024)
            src_port = 44552
            svc = "other"
            duration = round(random.uniform(0.001, 0.02), 3)
            bytes_sent = 60
            bytes_rcvd = 0
            packets = 1
            flags = "SYN"
            label = "PortScan"

        elif cat == "BruteForce":
            src = random.choice(external_attackers)
            dst = "192.168.1.20" # SSH bastion / Auth server
            proto = "TCP"
            svc = "ssh"
            dst_port = 22
            src_port = random.randint(40000, 50000)
            duration = round(random.uniform(0.1, 0.8), 3)
            bytes_sent = random.randint(800, 1500)
            bytes_rcvd = random.randint(800, 1500)
            packets = random.randint(8, 16)
            flags = "FIN"
            label = "BruteForce"

        elif cat == "WebExploit":
            src = random.choice(external_attackers)
            dst = "192.168.1.10"
            proto = "TCP"
            svc = "http"
            dst_port = 80
            src_port = random.randint(30000, 60000)
            duration = round(random.uniform(0.2, 1.2), 3)
            bytes_sent = random.randint(1200, 3500)
            bytes_rcvd = random.randint(200, 800)
            packets = random.randint(6, 15)
            flags = "ACK"
            label = "WebExploit"

        else: # Anomaly
            src = random.choice(internal_ips)
            dst = "198.51.100.99"
            proto = "UDP"
            svc = "unknown"
            dst_port = 61234
            src_port = 55432
            duration = round(random.uniform(5.0, 60.0), 3)
            bytes_sent = random.randint(100000, 5000000) # Unusual huge volume
            bytes_rcvd = 200
            packets = random.randint(500, 5000)
            flags = "PSH"
            label = "Anomaly"

        events.append({
            "timestamp": event_time.isoformat(),
            "source_ip": src,
            "destination_ip": dst,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": proto,
            "service": svc,
            "duration": duration,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_rcvd,
            "packet_count": packets,
            "flags": flags,
            "event_category": "NETWORK",
            "attack_type": label
        })

    return events

def export_synthetic_dataset_csv(filepath: str = None, count: int = 1000) -> str:
    """Save generated events to CSV file for ML training."""
    if not filepath:
        filepath = os.path.join(settings.DATA_STORAGE_DIR, "benchmark_cyber_events.csv")
    
    events = generate_synthetic_events(count)
    if not events:
        return filepath

    fieldnames = list(events[0].keys())
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
    return filepath
