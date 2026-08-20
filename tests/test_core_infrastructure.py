import pytest
from datetime import datetime, timezone
from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

from backend_server.config import Settings, get_settings
from backend_server.exceptions import (
    SentinelException,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    NotFoundError,
    RateLimitError,
    DeviceNotFoundError,
    DeviceAlreadyExistsError,
    ThreatAnalysisError,
    AIEngineError,
    SerialCommunicationError,
    WebSocketConnectionError,
    ConfigurationError
)
from backend_server.models.schemas import (
    validate_mac_address,
    ThreatSeverity,
    ThreatType,
    DeviceStatus,
    AIModelName,
    ChatMessage,
    ChatRequest,
    ThreatSimulationRequest,
    DeviceBlockRequest,
    DeviceWhitelistRequest,
    SerialDataRequest,
    ThreatInfo,
    DeviceInfo,
    StatsResponse,
    HealthResponse,
    ActionResponse,
    ErrorResponse
)
from backend_server.models.database import (
    ThreatModel,
    DeviceModel,
    ThreatCreate,
    ThreatUpdate,
    DeviceCreate,
    DeviceUpdate
)
from backend_server.routers.threats import (
    router as threats_router,
    calculate_severity,
    threat_history,
    total_threats_detected,
    get_threats,
    get_recent_threats,
    simulate_threat,
    clear_threats,
    delete_threat,
    get_threat_stats
)
from fastapi import FastAPI

def test_settings_initialization_and_cache():
    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.app_name == "Sentinel DevSecOps Platform"
    assert settings.port == 8000
    assert "http://localhost:5173" in settings.cors_origins
    
    # Test CORS parser validator with comma-separated string
    parsed_origins = Settings.parse_cors_origins("http://a.com, http://b.com")
    assert parsed_origins == ["http://a.com", "http://b.com"]

def test_exceptions_hierarchy_and_formatting():
    # Base Exception
    base_err = SentinelException("Test generic error", status_code=500, error_code="TEST_ERR", details={"foo": "bar"})
    err_dict = base_err.to_dict()
    assert err_dict["error"] == "TEST_ERR"
    assert err_dict["message"] == "Test generic error"
    assert err_dict["status_code"] == 500
    assert err_dict["details"] == {"foo": "bar"}

    # Derived Exceptions
    auth_err = AuthenticationError("Unauthorized token")
    assert auth_err.status_code == 401
    assert auth_err.error_code == "AUTHENTICATION_ERROR"

    authz_err = AuthorizationError("Forbidden access")
    assert authz_err.status_code == 403
    assert authz_err.error_code == "AUTHORIZATION_ERROR"

    val_err = ValidationError("Bad input")
    assert val_err.status_code == 400
    assert val_err.error_code == "VALIDATION_ERROR"

    nf_err = NotFoundError("Item not found")
    assert nf_err.status_code == 404
    assert nf_err.error_code == "NOT_FOUND"

    rl_err = RateLimitError("Too many requests")
    assert rl_err.status_code == 429
    assert rl_err.error_code == "RATE_LIMIT_EXCEEDED"

    dev_nf = DeviceNotFoundError("11:22:33:44:55:66")
    assert dev_nf.status_code == 404
    assert dev_nf.details["mac_address"] == "11:22:33:44:55:66"

    dev_exists = DeviceAlreadyExistsError("11:22:33:44:55:66")
    assert dev_exists.status_code == 409
    assert dev_exists.error_code == "DEVICE_ALREADY_EXISTS"

    assert ThreatAnalysisError().status_code == 500
    assert AIEngineError().status_code == 503
    assert SerialCommunicationError().status_code == 503
    assert WebSocketConnectionError().status_code == 503
    assert ConfigurationError().status_code == 500

def test_mac_validation_utility():
    assert validate_mac_address("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert validate_mac_address("00-11-22-33-44-55") == "00:11:22:33:44:55"
    with pytest.raises(ValueError):
        validate_mac_address("invalid-mac-address")

def test_pydantic_schemas_validation():
    # ChatRequest
    chat_req = ChatRequest(
        messages=[ChatMessage(role="user", content="hello")],
        model=AIModelName.LLAMA3_2_VISION
    )
    assert len(chat_req.messages) == 1
    assert chat_req.messages[0].content == "hello"

    # ThreatSimulationRequest
    sim_req = ThreatSimulationRequest(
        threat_type=ThreatType.DEAUTH,
        target_mac="aa:bb:cc:dd:ee:ff",
        duration_seconds=10,
        intensity="high"
    )
    assert sim_req.threat_type == ThreatType.DEAUTH
    assert sim_req.target_mac == "AA:BB:CC:DD:EE:FF"

    # DeviceBlockRequest
    block_req = DeviceBlockRequest(
        mac_address="00-11-22-33-44-55",
        duration_minutes=30,
        reason="Suspicious scan"
    )
    assert block_req.mac_address == "00:11:22:33:44:55"

    # DeviceWhitelistRequest
    wl_req = DeviceWhitelistRequest(
        mac_address="aa:bb:cc:dd:ee:ff",
        device_name="Admin Laptop"
    )
    assert wl_req.mac_address == "AA:BB:CC:DD:EE:FF"

    # ErrorResponse
    err_resp = ErrorResponse(
        error="TEST_ERR",
        message="A test error occurred",
        status_code=400
    )
    assert err_resp.status_code == 400

def test_database_models_to_dict():
    now = datetime.now(timezone.utc)
    threat = ThreatModel(
        id=1,
        external_id="ext-12345",
        timestamp=now,
        threat_type="DEAUTH",
        severity="high",
        source_mac="AA:BB:CC:DD:EE:01",
        target_mac="AA:BB:CC:DD:EE:02",
        channel=6,
        signal_strength=-45,
        description="Deauth attack detected",
        mitigation="Enable 802.11w PMF",
        ai_analyzed=True
    )
    d = threat.to_dict()
    assert d["id"] == "ext-12345"
    assert d["threat_type"] == "DEAUTH"
    assert d["severity"] == "high"
    assert d["ai_analyzed"] is True

    device = DeviceModel(
        id=1,
        mac_address="AA:BB:CC:DD:EE:01",
        status="online",
        first_seen=now,
        last_seen=now,
        device_name="ESP32 Sentinel",
        vendor="Espressif",
        is_whitelisted=True,
        is_blocked=False
    )
    dev_dict = device.to_dict()
    assert dev_dict["mac_address"] == "AA:BB:CC:DD:EE:01"
    assert dev_dict["is_whitelisted"] is True

    # Pydantic schemas for DB
    t_create = ThreatCreate(
        external_id="threat-99",
        threat_type="BEACON_FLOOD",
        severity="medium",
        description="Beacon flood test"
    )
    assert t_create.external_id == "threat-99"

    d_create = DeviceCreate(mac_address="11:22:33:44:55:66")
    assert d_create.status == "offline"

def test_calculate_severity():
    assert calculate_severity("DEAUTH", 1500, -40) == ThreatSeverity.CRITICAL.value
    assert calculate_severity("DEAUTH", 600, -40) == ThreatSeverity.HIGH.value
    assert calculate_severity("DEAUTH", 200, -40) == ThreatSeverity.MEDIUM.value
    assert calculate_severity("BEACON_FLOOD", 2500, -50) == ThreatSeverity.HIGH.value
    assert calculate_severity("BEACON_FLOOD", 1500, -50) == ThreatSeverity.MEDIUM.value
    assert calculate_severity("BEACON_FLOOD", 300, -50) == ThreatSeverity.LOW.value
    assert calculate_severity("EVIL_TWIN", 10, -30) == ThreatSeverity.HIGH.value
    assert calculate_severity("UNKNOWN_TYPE", 10, -30) == ThreatSeverity.MEDIUM.value

@pytest.mark.asyncio
async def test_threats_router_endpoints():
    from fastapi import Request
    from fastapi.responses import JSONResponse
    
    app = FastAPI()
    
    @app.exception_handler(SentinelException)
    async def sentinel_exception_handler(request: Request, exc: SentinelException):
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    app.include_router(threats_router)
    client = TestClient(app)

    # 1. Clear threats
    resp_clear = client.delete("/api/threats/clear")
    assert resp_clear.status_code == 200
    assert resp_clear.json()["success"] is True

    # 2. Get empty list
    resp_list = client.get("/api/threats")
    assert resp_list.status_code == 200
    data = resp_list.json()
    assert data["total_count"] == 0
    assert len(data["threats"]) == 0

    # 3. Simulate threat
    sim_payload = {
        "threat_type": "deauth",
        "target_mac": "AA:BB:CC:DD:EE:FF",
        "duration_seconds": 5,
        "intensity": "high"
    }
    resp_sim = client.post("/api/threats/simulate", json=sim_payload)
    assert resp_sim.status_code == 200
    res_data = resp_sim.json()
    assert res_data["success"] is True
    threat_id = res_data["data"]["threat_id"]

    # 4. Get threats list now has 1
    resp_list2 = client.get("/api/threats")
    assert resp_list2.status_code == 200
    assert resp_list2.json()["total_count"] == 1

    # 5. Get recent
    resp_recent = client.get("/api/threats/recent?count=5")
    assert resp_recent.status_code == 200
    assert len(resp_recent.json()) == 1

    # 6. Get stats
    resp_stats = client.get("/api/threats/stats")
    assert resp_stats.status_code == 200
    assert resp_stats.json()["total_threats"] == 1

    # 7. Delete specific threat
    resp_del = client.delete(f"/api/threats/{threat_id}")
    assert resp_del.status_code == 200

    # 8. Delete nonexistent threat raises 400
    resp_del_nf = client.delete("/api/threats/non-existent-id")
    assert resp_del_nf.status_code == 400
