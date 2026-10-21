import time
import requests
import random
import sys

API_BASE = "http://localhost:8000/api"

def login():
    try:
        res = requests.post(f"{API_BASE}/auth/login", json={"username": "admin", "password": "Admin@123"})
        if res.status_code == 200:
            return res.json()["access_token"]
        print("Login failed, please make sure backend is running.")
        sys.exit(1)
    except Exception as e:
        print(f"Error connecting to backend: {e}")
        print("Please start the backend server first by running: python -m uvicorn app.main:app --reload")
        sys.exit(1)

def run_simulation(token):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print("\n=======================================================")
    print("   CyberGuard AI - Live Attack Simulation Scenario")
    print("=======================================================")
    print("Injecting synthetic attacks into SOC stream every 2 seconds...\n")

    attack_scenarios = [
        {
            "name": "Distributed Denial of Service (SYN Flood)",
            "payload": {
                "source_ip": "185.220.101.5",
                "destination_ip": "192.168.1.10",
                "destination_port": 80,
                "protocol": "TCP",
                "service": "http",
                "duration": 0.005,
                "bytes_sent": 80,
                "bytes_received": 0,
                "packet_count": 2,
                "flags": "SYN"
            }
        },
        {
            "name": "SSH Brute-Force Authentication Attempt",
            "payload": {
                "source_ip": "45.154.255.88",
                "destination_ip": "192.168.1.20",
                "destination_port": 22,
                "protocol": "TCP",
                "service": "ssh",
                "duration": 0.35,
                "bytes_sent": 1200,
                "bytes_received": 1200,
                "packet_count": 12,
                "flags": "FIN"
            }
        },
        {
            "name": "Nmap Multi-Port Reconnaissance Sweep",
            "payload": {
                "source_ip": "194.26.29.112",
                "destination_ip": "192.168.1.55",
                "destination_port": random.randint(20, 1024),
                "protocol": "TCP",
                "service": "other",
                "duration": 0.01,
                "bytes_sent": 60,
                "bytes_received": 0,
                "packet_count": 1,
                "flags": "SYN"
            }
        },
        {
            "name": "Zero-Day Traffic Volume Anomaly",
            "payload": {
                "source_ip": "192.168.1.15",
                "destination_ip": "198.51.100.99",
                "destination_port": 61234,
                "protocol": "UDP",
                "service": "unknown",
                "duration": 25.0,
                "bytes_sent": 2500000,
                "bytes_received": 200,
                "packet_count": 1500,
                "flags": "PSH"
            }
        }
    ]

    for i in range(12):
        scenario = random.choice(attack_scenarios)
        print(f"[{i+1}/12] Launching Scenario: {scenario['name']} from {scenario['payload']['source_ip']}...")

        res = requests.post(f"{API_BASE}/ml/predict-intrusion", json=scenario["payload"], headers=headers)
        if res.status_code == 200:
            data = res.json()
            print(f"    ↳ Verdict: {data['threat_type']} | Risk: {data['risk_score']}/100 | Severity: {data['severity']} | Conf: {int(data['confidence']*100)}%")
        else:
            print(f"    ↳ Error: {res.status_code}")

        time.sleep(2)

    print("\n✓ Simulation scenario completed! Check your browser SOC dashboard at http://localhost:8000")

if __name__ == "__main__":
    token = login()
    run_simulation(token)
