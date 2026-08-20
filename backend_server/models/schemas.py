"""
Pydantic models for request/response validation.
Provides type safety and automatic documentation for API endpoints.
"""

import re
from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from enum import Enum

from pydantic import BaseModel, Field, field_validator, ConfigDict


# ============== Enums ==============

class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    """Types of network threats."""
    DEAUTH = "deauth"
    BEACON_FLOOD = "beacon_flood"
    PROBE_FLOOD = "probe_flood"
    EVIL_TWIN = "evil_twin"
    KRACK = "krack"
    UNKNOWN = "unknown"


class DeviceStatus(str, Enum):
    """Device connection status."""
    ONLINE = "online"
    OFFLINE = "offline"
    BLOCKED = "blocked"
    WHITELISTED = "whitelisted"


class AIModelName(str, Enum):
    """Available AI models."""
    LLAMA3_2_VISION = "llama3.2-vision"
    LLAMA3_2 = "llama3.2"
    MISTRAL = "mistral"
    PHI3 = "phi3"


# ============== MAC Address Validation ==============

MAC_ADDRESS_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')


def validate_mac_address(mac: str) -> str:
    """Validate and normalize MAC address format."""
    if not MAC_ADDRESS_PATTERN.match(mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return mac.upper().replace('-', ':')


# ============== Request Models ==============

class ChatMessage(BaseModel):
    """Chat message for AI agent conversation."""
    role: Literal["user", "assistant", "system"] = Field(..., description="Message role")
    content: str = Field(..., min_length=1, max_length=10000, description="Message content")


class ChatRequest(BaseModel):
    """Request model for chat endpoint."""
    messages: List[ChatMessage] = Field(..., min_length=1, description="Conversation history")
    model: Optional[AIModelName] = Field(default=AIModelName.LLAMA3_2_VISION, description="AI model to use")
    stream: bool = Field(default=False, description="Whether to stream response")
    
    model_config = ConfigDict(json_schema_extra={
        "examples": [
            {
                "messages": [
                    {"role": "user", "content": "What is a deauthentication attack?"}
                ],
                "model": "llama3.2-vision",
                "stream": False
            }
        ]
    })


class ThreatSimulationRequest(BaseModel):
    """Request model for threat simulation."""
    threat_type: ThreatType = Field(..., description="Type of threat to simulate")
    target_mac: Optional[str] = Field(default=None, description="Target MAC address")
    duration_seconds: int = Field(default=5, ge=1, le=60, description="Simulation duration")
    intensity: Literal["low", "medium", "high"] = Field(default="medium", description="Attack intensity")
    
    @field_validator('target_mac')
    @classmethod
    def validate_target_mac(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_mac_address(v)
        return v
    
    model_config = ConfigDict(json_schema_extra={
        "examples": [
            {
                "threat_type": "deauth",
                "target_mac": "AA:BB:CC:DD:EE:FF",
                "duration_seconds": 5,
                "intensity": "medium"
            }
        ]
    })


class DeviceBlockRequest(BaseModel):
    """Request model for blocking a device."""
    mac_address: str = Field(..., description="MAC address to block")
    duration_minutes: Optional[int] = Field(default=60, ge=1, le=1440, description="Block duration")
    reason: Optional[str] = Field(default=None, max_length=200, description="Reason for blocking")
    
    @field_validator('mac_address')
    @classmethod
    def validate_mac(cls, v: str) -> str:
        return validate_mac_address(v)
    
    model_config = ConfigDict(json_schema_extra={
        "examples": [
            {
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "duration_minutes": 60,
                "reason": "Suspicious activity detected"
            }
        ]
    })


class DeviceWhitelistRequest(BaseModel):
    """Request model for whitelisting a device."""
    mac_address: str = Field(..., description="MAC address to whitelist")
    device_name: Optional[str] = Field(default=None, max_length=100, description="Friendly device name")
    description: Optional[str] = Field(default=None, max_length=500, description="Device description")
    
    @field_validator('mac_address')
    @classmethod
    def validate_mac(cls, v: str) -> str:
        return validate_mac_address(v)


class SerialDataRequest(BaseModel):
    """Request model for sending serial data."""
    data: str = Field(..., min_length=1, max_length=10000, description="Data to send")
    timeout: float = Field(default=1.0, ge=0.1, le=30.0, description="Operation timeout")


# ============== Response Models ==============

class ChatResponse(BaseModel):
    """Response model for chat endpoint."""
    message: ChatMessage = Field(..., description="AI response message")
    model_used: str = Field(..., description="AI model that generated the response")
    processing_time_ms: float = Field(..., description="Time taken to generate response")
    confidence_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Response confidence")
    
    model_config = ConfigDict(json_schema_extra={
        "examples": [
            {
                "message": {"role": "assistant", "content": "A deauthentication attack..."},
                "model_used": "llama3.2-vision",
                "processing_time_ms": 1250.5,
                "confidence_score": 0.92
            }
        ]
    })


class ThreatInfo(BaseModel):
    """Threat information model."""
    id: str = Field(..., description="Unique threat identifier")
    timestamp: datetime = Field(..., description="When threat was detected")
    threat_type: ThreatType = Field(..., description="Type of threat")
    severity: ThreatSeverity = Field(..., description="Threat severity level")
    source_mac: Optional[str] = Field(default=None, description="Source MAC address")
    target_mac: Optional[str] = Field(default=None, description="Target MAC address")
    channel: Optional[int] = Field(default=None, ge=1, le=14, description="WiFi channel")
    signal_strength: Optional[int] = Field(default=None, ge=-100, le=-1, description="Signal strength in dBm")
    description: str = Field(..., description="Threat description")
    mitigation: Optional[str] = Field(default=None, description="Suggested mitigation")
    ai_analyzed: bool = Field(default=False, description="Whether AI has analyzed this threat")
    
    model_config = ConfigDict(from_attributes=True)


class ThreatListResponse(BaseModel):
    """Response model for threat list endpoint."""
    threats: List[ThreatInfo] = Field(..., description="List of threats")
    total_count: int = Field(..., description="Total number of threats")
    filtered_count: int = Field(..., description="Number of threats after filtering")
    
    model_config = ConfigDict(json_schema_extra={
        "examples": [
            {
                "threats": [],
                "total_count": 0,
                "filtered_count": 0
            }
        ]
    })


class DeviceInfo(BaseModel):
    """Device information model."""
    mac_address: str = Field(..., description="Device MAC address")
    status: DeviceStatus = Field(..., description="Current device status")
    first_seen: datetime = Field(..., description="When device was first detected")
    last_seen: datetime = Field(..., description="Last time device was seen")
    device_name: Optional[str] = Field(default=None, description="Friendly device name")
    vendor: Optional[str] = Field(default=None, description="Device vendor (OUI)")
    is_whitelisted: bool = Field(default=False, description="Whether device is whitelisted")
    is_blocked: bool = Field(default=False, description="Whether device is blocked")
    block_reason: Optional[str] = Field(default=None, description="Reason for blocking")
    block_expires: Optional[datetime] = Field(default=None, description="When block expires")
    
    model_config = ConfigDict(from_attributes=True)


class DeviceListResponse(BaseModel):
    """Response model for device list endpoint."""
    devices: List[DeviceInfo] = Field(..., description="List of devices")
    total_count: int = Field(..., description="Total number of devices")
    online_count: int = Field(..., description="Number of online devices")
    blocked_count: int = Field(..., description="Number of blocked devices")
    whitelisted_count: int = Field(..., description="Number of whitelisted devices")


class StatsResponse(BaseModel):
    """System statistics response model."""
    uptime_seconds: float = Field(..., description="System uptime in seconds")
    total_threats_detected: int = Field(..., description="Total threats detected")
    threats_last_hour: int = Field(..., description="Threats in last hour")
    total_devices: int = Field(..., description="Total devices seen")
    active_devices: int = Field(..., description="Currently active devices")
    blocked_devices: int = Field(..., description="Currently blocked devices")
    websocket_clients: int = Field(..., description="Connected WebSocket clients")
    ai_model_status: str = Field(..., description="AI model availability status")
    serial_connected: bool = Field(..., description="Whether serial device is connected")
    memory_usage_mb: float = Field(..., description="Memory usage in MB")
    cpu_usage_percent: float = Field(..., description="CPU usage percentage")


class HealthResponse(BaseModel):
    """Health check response model."""
    status: Literal["healthy", "degraded", "unhealthy"] = Field(..., description="Overall health status")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(..., description="Check timestamp")
    components: Dict[str, Dict[str, Any]] = Field(..., description="Component health status")
    
    model_config = ConfigDict(json_schema_extra={
        "examples": [
            {
                "status": "healthy",
                "version": "3.5.0",
                "timestamp": "2024-01-01T00:00:00Z",
                "components": {
                    "api": {"status": "healthy", "latency_ms": 5},
                    "ai_engine": {"status": "healthy", "model_loaded": True},
                    "serial": {"status": "degraded", "message": "No device connected"},
                    "websocket": {"status": "healthy", "clients": 3}
                }
            }
        ]
    })


class ActionResponse(BaseModel):
    """Generic action response model."""
    success: bool = Field(..., description="Whether action succeeded")
    message: str = Field(..., description="Result message")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Additional data")


class ErrorResponse(BaseModel):
    """Standardized error response model."""
    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    status_code: int = Field(..., description="HTTP status code")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")
    
    model_config = ConfigDict(json_schema_extra={
        "examples": [
            {
                "error": "VALIDATION_ERROR",
                "message": "Invalid MAC address format",
                "status_code": 400,
                "details": {"field": "mac_address"}
            }
        ]
    })
