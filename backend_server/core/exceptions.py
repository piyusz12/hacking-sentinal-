"""
Custom exception classes for Project Sentinel
Standardized error handling across the application
"""
from typing import Any, Dict, Optional
from fastapi import HTTPException, status


class SentinelException(Exception):
    """Base exception for Project Sentinel"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            **self.details
        }


class HardwareCommunicationError(SentinelException):
    """Raised when hardware communication fails (ESP32, OLED, Buzzer, etc.)"""
    pass


class AIPipelineError(SentinelException):
    """Raised when AI pipeline execution fails"""
    pass


class VectorDatabaseError(SentinelException):
    """Raised when FAISS vector database operations fail"""
    pass


class ThreatDetectionError(SentinelException):
    """Raised when threat detection logic encounters an error"""
    pass


class InvalidFrameDataError(SentinelException):
    """Raised when received frame data is malformed or invalid"""
    pass


class AuthenticationError(HTTPException):
    """Raised when authentication fails"""
    
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"}
        )


class AuthorizationError(HTTPException):
    """Raised when user lacks required permissions"""
    
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )


class RateLimitExceeded(HTTPException):
    """Raised when rate limit is exceeded"""
    
    def __init__(self, retry_after: int = 60):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)}
        )


class DeviceNotFoundError(HTTPException):
    """Raised when a device is not found"""
    
    def __init__(self, mac_address: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with MAC address {mac_address} not found"
        )


class ThreatSimulationError(HTTPException):
    """Raised when threat simulation fails"""
    
    def __init__(self, detail: str = "Failed to simulate threat"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )
