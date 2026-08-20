"""
Centralized configuration management for Sentinel DevSecOps Platform.
Uses Pydantic Settings for environment variable validation and type safety.
"""

import secrets
from functools import lru_cache
from typing import Optional, List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Application
    app_name: str = "Sentinel DevSecOps Platform"
    app_version: str = "3.5.0"
    debug: bool = False
    environment: str = Field(default="development", description="deployment environment")
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = True
    
    # Security - CRITICAL: These should be overridden in production
    ws_auth_token: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="WebSocket authentication token"
    )
    api_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="API key for authentication"
    )
    jwt_secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for JWT token generation"
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # CORS - Restricted origins
    cors_origins: List[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
        description="Allowed CORS origins"
    )
    
    @field_validator('cors_origins', mode='before')
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(',')]
        return v
    
    # Rate Limiting
    rate_limit_requests: int = 100  # requests per window
    rate_limit_window_seconds: int = 60
    
    # Database
    database_url: Optional[str] = Field(
        default=None,
        description="SQLite or PostgreSQL connection string"
    )
    
    # Redis (optional caching layer)
    redis_url: Optional[str] = Field(
        default=None,
        description="Redis connection URL"
    )
    cache_ttl_seconds: int = 30
    
    # AI/LLM Configuration
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2-vision"
    ollama_timeout_seconds: float = 120.0
    use_local_embeddings: bool = True
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_dimension: int = 384
    
    # Vector Database
    vector_db_path: str = "./vector_store"
    max_vector_results: int = 5
    
    # Chat History
    max_chat_history: int = 6
    
    # Threat Management
    max_threat_history: int = 200
    threat_retention_hours: int = 24
    
    # WebSocket
    max_dashboard_clients: int = 50
    websocket_ping_interval: int = 30
    websocket_ping_timeout: int = 10
    
    # Serial Communication
    serial_port: Optional[str] = None
    serial_baudrate: int = 115200
    serial_timeout: float = 1.0
    
    # Device Management
    default_block_duration_minutes: int = 60
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text
    log_file: Optional[str] = "./logs/sentinel.log"
    
    # Monitoring
    enable_prometheus_metrics: bool = False
    prometheus_port: int = 9090
    
    # Feature Flags
    enable_ai_analysis: bool = True
    enable_threat_simulation: bool = True
    enable_device_blocking: bool = True


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Uses LRU cache to avoid reloading settings on every request.
    """
    return Settings()


# Convenience exports
settings = get_settings()
