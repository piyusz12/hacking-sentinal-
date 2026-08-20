"""
Core configuration and security settings for Project Sentinel
Centralized environment variable management with Pydantic Settings
"""
import os
import secrets
from functools import lru_cache
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application
    app_name: str = "Project Sentinel"
    app_version: str = "3.5.0"
    debug: bool = False
    environment: str = "development"
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000"
    ]
    
    # Security - Auto-generated secure tokens if not provided
    ws_auth_token: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    api_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_secret: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    
    # Rate Limiting
    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 10
    
    # AI/LLM Configuration
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    ollama_vision_model: str = "llama3.2-vision"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    use_local_embeddings: bool = True
    max_context_messages: int = 6
    ai_timeout_seconds: float = 45.0
    
    # Vector Database
    faiss_index_path: str = "./vector_index"
    vector_dimension: int = 384  # Matches MiniLM-L6
    
    # Database
    database_url: str = "sqlite+aiosqlite:///./sentinel.db"
    
    # Redis Cache (optional)
    redis_url: Optional[str] = None
    cache_ttl_seconds: int = 30
    
    # WebSocket
    max_dashboard_clients: int = 50
    heartbeat_interval: float = 30.0
    
    # Serial Communication
    serial_port: Optional[str] = None
    serial_baud_rate: int = 115200
    serial_timeout: float = 1.0
    
    # Threat Detection
    threat_history_limit: int = 200
    deauth_threshold_per_second: int = 5
    probe_flood_threshold_per_second: int = 20
    sliding_window_seconds: int = 3
    
    # Hardware Integration
    enable_hardware_feedback: bool = True
    oled_enabled: bool = True
    buzzer_gpio: int = 16
    neopixel_gpio: int = 48
    speaker_i2s_enabled: bool = True
    
    # Monitoring
    prometheus_enabled: bool = False
    prometheus_port: int = 9090
    otel_exporter_endpoint: Optional[str] = None
    
    @field_validator('cors_origins', mode='before')
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(',')]
        return v
    
    @field_validator('environment')
    @classmethod
    def validate_environment(cls, v):
        allowed = ['development', 'staging', 'production']
        if v not in allowed:
            raise ValueError(f'Environment must be one of: {allowed}')
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
