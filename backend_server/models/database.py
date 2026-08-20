"""
Pydantic models for database persistence.
Used with SQLAlchemy ORM for threat and device storage.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class ThreatModel(Base):
    """SQLAlchemy model for threat storage."""
    
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    external_id = Column(String(36), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    threat_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    source_mac = Column(String(17), nullable=True)
    target_mac = Column(String(17), nullable=True)
    channel = Column(Integer, nullable=True)
    signal_strength = Column(Integer, nullable=True)
    description = Column(Text, nullable=False)
    mitigation = Column(Text, nullable=True)
    ai_analyzed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.external_id,
            "timestamp": self.timestamp.isoformat(),
            "threat_type": self.threat_type,
            "severity": self.severity,
            "source_mac": self.source_mac,
            "target_mac": self.target_mac,
            "channel": self.channel,
            "signal_strength": self.signal_strength,
            "description": self.description,
            "mitigation": self.mitigation,
            "ai_analyzed": self.ai_analyzed
        }


class DeviceModel(Base):
    """SQLAlchemy model for device storage."""
    
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(17), unique=True, nullable=False, index=True)
    status = Column(String(20), default="offline")
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    device_name = Column(String(100), nullable=True)
    vendor = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    is_whitelisted = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    block_reason = Column(Text, nullable=True)
    block_expires = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "mac_address": self.mac_address,
            "status": self.status,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "device_name": self.device_name,
            "vendor": self.vendor,
            "is_whitelisted": self.is_whitelisted,
            "is_blocked": self.is_blocked,
            "block_reason": self.block_reason,
            "block_expires": self.block_expires.isoformat() if self.block_expires else None
        }


# Pydantic schemas for DB operations
class ThreatCreate(BaseModel):
    """Schema for creating a threat record."""
    external_id: str = Field(..., description="Unique threat identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    threat_type: str = Field(..., description="Type of threat")
    severity: str = Field(..., description="Severity level")
    source_mac: Optional[str] = None
    target_mac: Optional[str] = None
    channel: Optional[int] = None
    signal_strength: Optional[int] = None
    description: str = Field(..., description="Threat description")
    mitigation: Optional[str] = None
    ai_analyzed: bool = False


class ThreatUpdate(BaseModel):
    """Schema for updating a threat record."""
    severity: Optional[str] = None
    mitigation: Optional[str] = None
    ai_analyzed: Optional[bool] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class DeviceCreate(BaseModel):
    """Schema for creating a device record."""
    mac_address: str = Field(..., description="Device MAC address")
    status: str = Field(default="offline")
    device_name: Optional[str] = None
    vendor: Optional[str] = None
    description: Optional[str] = None
    is_whitelisted: bool = False
    is_blocked: bool = False
    block_reason: Optional[str] = None
    block_expires: Optional[datetime] = None


class DeviceUpdate(BaseModel):
    """Schema for updating a device record."""
    status: Optional[str] = None
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    device_name: Optional[str] = None
    vendor: Optional[str] = None
    is_whitelisted: Optional[bool] = None
    is_blocked: Optional[bool] = None
    block_reason: Optional[str] = None
    block_expires: Optional[datetime] = None
