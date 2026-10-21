@echo off
echo =======================================================
echo          Running CyberGuard AI Test Suite
echo =======================================================
call .venv\Scripts\activate
python -m pytest tests/ -v
pause
