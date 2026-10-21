import os
from typing import List

class Settings:
    PROJECT_NAME: str = "CyberGuard AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = os.getenv("CYBERGUARD_SECRET_KEY", "cyberguard-ai-soc-super-secret-key-2026-secure")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cyberguard.db")
    
    # ML & Threat Detection Settings
    ANOMALY_THRESHOLD: float = 0.65
    BRUTE_FORCE_WINDOW_SECONDS: int = 300  # 5 minutes
    BRUTE_FORCE_MAX_ATTEMPTS: int = 5
    PORT_SCAN_WINDOW_SECONDS: int = 60    # 1 minute
    PORT_SCAN_PORT_THRESHOLD: int = 10
    
    # Models & Datasets Storage
    MODEL_STORAGE_DIR: str = os.getenv("MODEL_STORAGE_DIR", "./models_storage")
    DATA_STORAGE_DIR: str = os.getenv("DATA_STORAGE_DIR", "./data_storage")
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]

settings = Settings()
os.makedirs(settings.MODEL_STORAGE_DIR, exist_ok=True)
os.makedirs(settings.DATA_STORAGE_DIR, exist_ok=True)
