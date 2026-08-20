"""
Custom exception classes for Sentinel DevSecOps Platform.
Provides standardized error handling across the application.
"""

from typing import Any, Optional, Dict


class SentinelException(Exception):
    """Base exception for all Sentinel platform errors."""
    
    def __init__(
        self,
        message: str,
        status_code: int = 500,
        error_code: str = "UNKNOWN_ERROR",
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON response."""
        return {
            "error": self.error_code,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details
        }


class AuthenticationError(SentinelException):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=401,
            error_code="AUTHENTICATION_ERROR",
            details=details
        )


class AuthorizationError(SentinelException):
    """Raised when user lacks permission for an action."""
    
    def __init__(self, message: str = "Authorization failed", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=403,
            error_code="AUTHORIZATION_ERROR",
            details=details
        )


class ValidationError(SentinelException):
    """Raised when input validation fails."""
    
    def __init__(self, message: str = "Validation error", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=400,
            error_code="VALIDATION_ERROR",
            details=details
        )


class NotFoundError(SentinelException):
    """Raised when a requested resource is not found."""
    
    def __init__(self, message: str = "Resource not found", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=404,
            error_code="NOT_FOUND",
            details=details
        )


class RateLimitError(SentinelException):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            details=details
        )


class DeviceNotFoundError(NotFoundError):
    """Raised when a device is not found."""
    
    def __init__(self, mac_address: str):
        super().__init__(
            message=f"Device with MAC address {mac_address} not found",
            details={"mac_address": mac_address}
        )


class DeviceAlreadyExistsError(SentinelException):
    """Raised when attempting to add a duplicate device."""
    
    def __init__(self, mac_address: str):
        super().__init__(
            message=f"Device with MAC address {mac_address} already exists",
            status_code=409,
            error_code="DEVICE_ALREADY_EXISTS",
            details={"mac_address": mac_address}
        )


class ThreatAnalysisError(SentinelException):
    """Raised when threat analysis fails."""
    
    def __init__(self, message: str = "Threat analysis failed", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=500,
            error_code="THREAT_ANALYSIS_ERROR",
            details=details
        )


class AIEngineError(SentinelException):
    """Raised when AI engine operations fail."""
    
    def __init__(self, message: str = "AI engine error", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=503,
            error_code="AI_ENGINE_ERROR",
            details=details
        )


class SerialCommunicationError(SentinelException):
    """Raised when serial communication fails."""
    
    def __init__(self, message: str = "Serial communication error", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=503,
            error_code="SERIAL_COMMUNICATION_ERROR",
            details=details
        )


class WebSocketConnectionError(SentinelException):
    """Raised when WebSocket connection fails."""
    
    def __init__(self, message: str = "WebSocket connection error", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=503,
            error_code="WEBSOCKET_CONNECTION_ERROR",
            details=details
        )


class ConfigurationError(SentinelException):
    """Raised when configuration is invalid."""
    
    def __init__(self, message: str = "Configuration error", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=500,
            error_code="CONFIGURATION_ERROR",
            details=details
        )
class InvalidFrameDataError(SentinelException):
    """Raised when received frame data is malformed or invalid"""
    
    def __init__(self, message: str = "Invalid frame data", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=400,
            error_code="INVALID_FRAME_DATA",
            details=details
        )


class ThreatSimulationError(SentinelException):
    """Raised when threat simulation fails"""
    
    def __init__(self, message: str = "Failed to simulate threat", details: Optional[Dict] = None):
        super().__init__(
            message=message,
            status_code=500,
            error_code="SIMULATION_ERROR",
            details=details
        )
