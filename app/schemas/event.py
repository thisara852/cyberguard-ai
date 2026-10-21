from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, List
from datetime import datetime
import ipaddress

class SecurityEventCreate(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: str
    destination_ip: str
    source_port: int = Field(default=0, ge=0, le=65535)
    destination_port: int = Field(default=80, ge=0, le=65535)
    protocol: str = Field(default="TCP")
    service: str = Field(default="http")
    duration: float = Field(default=0.1, ge=0.0)
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)
    packet_count: int = Field(default=1, ge=1)
    flags: str = Field(default="SYN")
    event_category: str = Field(default="NETWORK")
    raw_payload: Optional[str] = None

    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
            return v.strip()
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")

    @field_validator('protocol')
    @classmethod
    def normalize_protocol(cls, v: str) -> str:
        return v.strip().upper()

    @field_validator('service')
    @classmethod
    def normalize_service(cls, v: str) -> str:
        return v.strip().lower()

class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    service: str
    duration: float
    bytes_sent: int
    bytes_received: int
    packet_count: int
    flags: str
    event_category: str
    raw_payload: Optional[str] = None
    is_processed: bool

class SecurityEventBatch(BaseModel):
    events: List[SecurityEventCreate]

class IngestionSummary(BaseModel):
    total_received: int
    accepted: int
    rejected: int
    errors: List[str] = []
