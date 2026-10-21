@echo off
echo =======================================================
echo          Starting CyberGuard AI SOC Server
echo =======================================================
call .venv\Scripts\activate
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
