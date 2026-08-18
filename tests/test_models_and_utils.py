import pytest
from pydantic import ValidationError
from backend_server.main import (
    ThreatPayload,
    SimulationRequest,
    AiChatRequest,
    ImageAnalysisRequest,
    SetModelRequest,
    DeviceItem,
    SerialConnectRequest,
    verify_ws_token,
    ConnectionManager
)

def test_threat_payload_mac_validation():
    # Valid MAC
    payload = ThreatPayload(
        threat_type="DEAUTH",
        attacker_mac="00:11:22:33:44:55",
        target_mac="aa-bb-cc-dd-ee-ff"
    )
    assert payload.attacker_mac == "00:11:22:33:44:55"
    assert payload.target_mac == "aa-bb-cc-dd-ee-ff"

    # Invalid MAC should fallback to default safely
    payload_invalid = ThreatPayload(
        threat_type="DEAUTH",
        attacker_mac="INVALID_MAC_STRING",
        target_mac="12345"
    )
    assert payload_invalid.attacker_mac == "DE:AD:BE:EF:00:01"
    assert payload_invalid.target_mac == "DE:AD:BE:EF:00:01"

def test_threat_payload_sanitization():
    # Threat type with special / malicious chars
    payload = ThreatPayload(
        threat_type="DEAUTH<script>alert(1)</script>_STORM!@#",
        channel=6,
        rssi=-50
    )
    assert "<" not in payload.threat_type
    assert ">" not in payload.threat_type
    assert "!" not in payload.threat_type
    assert payload.threat_type == "DEAUTHscriptalert1script_STORM"

def test_threat_payload_bounds():
    # Channel out of bounds should raise ValidationError
    with pytest.raises(ValidationError):
        ThreatPayload(threat_type="DEAUTH", channel=15)

    with pytest.raises(ValidationError):
        ThreatPayload(threat_type="DEAUTH", channel=0)

    # RSSI out of bounds
    with pytest.raises(ValidationError):
        ThreatPayload(threat_type="DEAUTH", rssi=10)

def test_simulation_request():
    req = SimulationRequest(
        threat_type="EVIL_TWIN",
        attacker_mac="E0:5A:1B:99:33:AA",
        channel=1,
        rssi=-35,
        packet_count=920
    )
    assert req.threat_type == "EVIL_TWIN"
    assert req.channel == 1
    assert req.rssi == -35
    assert req.packet_count == 920

def test_ai_chat_request():
    req = AiChatRequest(
        query="What is PMF?",
        context_threat_type="DEAUTH_STORM",
        chat_history=[{"role": "user", "content": "hello"}]
    )
    assert req.query == "What is PMF?"
    assert req.context_threat_type == "DEAUTH_STORM"
    assert len(req.chat_history) == 1

def test_verify_ws_token():
    # Empty token allows dev connect
    assert verify_ws_token(None) is True
    assert verify_ws_token("") is True

    # Default dev token
    assert verify_ws_token("sentinel-dev-token-change-me") is True

    # Bad token
    assert verify_ws_token("completely_wrong_secret_token") is False

def test_device_item_model():
    dev = DeviceItem(
        mac="A4:C3:F0:12:34:56",
        ip="10.0.1.101",
        name="Test MacBook",
        vendor="Apple Inc.",
        trusted=True,
        rssi=-48
    )
    assert dev.mac == "A4:C3:F0:12:34:56"
    assert dev.trusted is True

def test_serial_connect_request():
    req = SerialConnectRequest(port="COM3", baud_rate=115200)
    assert req.port == "COM3"
    assert req.baud_rate == 115200
