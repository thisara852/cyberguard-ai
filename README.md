# CyberGuard AI: Cloud-Based Cybersecurity Monitoring, Intelligent Threat Detection & Incident Response Platform

CyberGuard AI is an end-to-end, production-style cybersecurity monitoring system and Security Operations Center (SOC) platform designed to detect abnormal network behavior, classify intrusions using machine learning, compute composite risk scores, deliver real-time WebSocket alerts, and automate incident response playbooks.

---

## 10-Day Implementation Architecture

| Day | Milestone | Key Modules & Deliverables |
| :--- | :--- | :--- |
| **Day 1** | **Architecture, DB & RBAC Auth** | FastAPI application setup, SQLite/PostgreSQL models, PBKDF2 hashing, JWT tokens, RBAC (`Super Admin`, `Security Analyst`, `Normal User`), Audit logging (`FR-01` to `FR-05`, `FR-42`). |
| **Day 2** | **Data Ingestion & Normalization** | CSV/JSON ingestion pipeline, schema validation, network field normalization, synthetic benchmark dataset generator (`FR-06` to `FR-09`, `FR-43`). |
| **Day 3** | **Supervised Intrusion ML Engine** | Feature engineering pipeline, Random Forest classifier, model evaluation (Accuracy, Precision, Recall, F1, Confusion Matrix), model registry (`FR-10`, `FR-16`, `FR-44` to `FR-47`). |
| **Day 4** | **Unsupervised Anomaly & Stateful Detectors** | Isolation Forest continuous anomaly scoring, sliding-window Brute-Force detector, multi-port Reconnaissance sweep detector (`FR-11` to `FR-13`). |
| **Day 5** | **Phishing, Malware & UEBA** | Lexical & entropy URL phishing classifier, PE header & signature malware analyzer, User & Entity Behavior Analytics baseline engine (`FR-14`, `FR-15`, `FR-29`, `FR-30`). |
| **Day 6** | **Composite Risk Engine & Live Alerts** | Unified 0–100 composite risk scoring with explainability factors, alert deduplication, real-time WebSocket push notifications (`FR-17` to `FR-22`, `FR-31`, `FR-52`). |
| **Day 7** | **Incident Management & Response** | Incident lifecycle (`NEW` $\to$ `INVESTIGATING` $\to$ `CONTAINED` $\to$ `RESOLVED` $\to$ `CLOSED`), chronological timeline, evidence locker, simulated playbooks (`BLOCK_IP`, `DISABLE_USER`, `ISOLATE_DEVICE`, `QUARANTINE_FILE`) (`FR-23` to `FR-28`, `FR-39` to `FR-41`). |
| **Day 8** | **Interactive SOC Dashboard & Graph** | Real-time dark-mode SOC web console, canvas-based animated Attack Topology graph, temporal trend curves, asset risk ranking (`FR-32` to `FR-36`, `NFR-08`, `NFR-10`). |
| **Day 9** | **AI Security Copilot & MLOps Drift** | Natural language AI SOC Copilot for query answering and threat summaries, MLOps telemetry monitor (latency, throughput), Population Stability Index (PSI) data drift detection (`FR-37`, `FR-38`, `FR-48` to `FR-51`). |
| **Day 10** | **Admin, End-to-End Tests & Demo** | System thresholds config, database backup, automated test suite covering all modules, and real-time live attack traffic simulation runner (`FR-53` to `FR-55`, `NFR-01` to `NFR-16`). |

---

## Quick Start Guide

### 1. Requirements
- Python 3.10+ (Installed via `uv` or system Python)
- Modern web browser (Chrome, Edge, Firefox)

### 2. Running the Platform
Double-click `run_server.bat` or run in terminal:
```powershell
.venv\Scripts\activate
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
