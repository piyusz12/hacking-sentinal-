"""Core package for Project Sentinel"""
from backend_server.core.config import Settings, get_settings
from backend_server.core.exceptions import (
    SentinelException,
    HardwareCommunicationError,
    AIPipelineError,
    VectorDatabaseError,
    ThreatDetectionError,
    InvalidFrameDataError,
    AuthenticationError,
    AuthorizationError,
    RateLimitExceeded,
    DeviceNotFoundError,
    ThreatSimulationError
)

__all__ = [
    "Settings",
    "get_settings",
    "SentinelException",
    "HardwareCommunicationError",
    "AIPipelineError",
    "VectorDatabaseError",
    "ThreatDetectionError",
    "InvalidFrameDataError",
    "AuthenticationError",
    "AuthorizationError",
    "RateLimitExceeded",
    "DeviceNotFoundError",
    "ThreatSimulationError"
]
