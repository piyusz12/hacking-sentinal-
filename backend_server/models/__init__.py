"""
Models package for Sentinel DevSecOps Platform.
Provides Pydantic schemas and SQLAlchemy models.
"""

from backend_server.models.schemas import (
    # Enums
    ThreatSeverity,
    ThreatType,
    DeviceStatus,
    AIModelName,
    # Request models
    ChatMessage,
    ChatRequest,
    ThreatSimulationRequest,
    DeviceBlockRequest,
    DeviceWhitelistRequest,
    SerialDataRequest,
    # Response models
    ChatResponse,
    ThreatInfo,
    ThreatListResponse,
    DeviceInfo,
    DeviceListResponse,
    StatsResponse,
    HealthResponse,
    ActionResponse,
    ErrorResponse,
    # Validators
    validate_mac_address,
    MAC_ADDRESS_PATTERN,
)

from backend_server.models.database import (
    Base,
    ThreatModel,
    DeviceModel,
    ThreatCreate,
    ThreatUpdate,
    DeviceCreate,
    DeviceUpdate,
)

__all__ = [
    # Enums
    "ThreatSeverity",
    "ThreatType",
    "DeviceStatus",
    "AIModelName",
    # Request models
    "ChatMessage",
    "ChatRequest",
    "ThreatSimulationRequest",
    "DeviceBlockRequest",
    "DeviceWhitelistRequest",
    "SerialDataRequest",
    # Response models
    "ChatResponse",
    "ThreatInfo",
    "ThreatListResponse",
    "DeviceInfo",
    "DeviceListResponse",
    "StatsResponse",
    "HealthResponse",
    "ActionResponse",
    "ErrorResponse",
    # Validators
    "validate_mac_address",
    "MAC_ADDRESS_PATTERN",
    # Database models
    "Base",
    "ThreatModel",
    "DeviceModel",
    "ThreatCreate",
    "ThreatUpdate",
    "DeviceCreate",
    "DeviceUpdate",
]
