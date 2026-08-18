import os
import io
import csv
import json
import pytest
from fastapi.testclient import TestClient
from backend_server.main import (
    app,
    threat_history,
    devices_registry,
    total_threats_detected,
    serial_bridge_state,
    local_ai_engine
)

@pytest.fixture
def client():
    # Use TestClient with lifespan context
    with TestClient(app) as test_client:
        yield test_client

def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Sentinel DevSecOps & Wi-Fi IDS AI Platform"
    assert data["status"] == "ONLINE"
    assert data["version"] == "3.5.0"
    assert "uptime_seconds" in data
    assert "local_ai" in data
    assert data["docs_url"] == "/docs"

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "uptime_seconds" in data
    assert "system" in data
    assert "dashboard_clients" in data
    assert "esp32_clients" in data
    assert "ai_engine" in data

def test_get_stats(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "threats_count" in data
    assert data["active_channel"] == 6
    assert data["base_ssid"] == "HomeNet_5G"
    assert "ai_engine" in data

def test_simulate_threat_and_history(client):
    # Simulate a deauth attack
    payload = {
        "threat_type": "DEAUTH_STORM",
        "attacker_mac": "DE:AD:BE:EF:00:01",
        "target_mac": "AA:BB:CC:DD:EE:FF",
        "channel": 6,
        "rssi": -45,
        "packet_count": 500
    }
    sim_res = client.post("/api/threats/simulate", json=payload)
    assert sim_res.status_code == 200
    data = sim_res.json()
    assert data["success"] is True
    assert "DEAUTH_STORM" in data["message"]

    # Verify threat was recorded in threat history
    threats_res = client.get("/api/threats")
    assert threats_res.status_code == 200
    threats_data = threats_res.json()
    assert "count" in threats_data
    assert "threats" in threats_data

    # Test filtering by threat type
    filter_res = client.get("/api/threats?threat_type=DEAUTH")
    assert filter_res.status_code == 200
    filter_data = filter_res.json()
    assert filter_data["count"] >= 0

def test_threat_export_json_and_csv(client):
    # Add a mock entry to threat history for export verification
    threat_history.insert(0, {
        "type": "ai_report",
        "threat": "0x0C Deauth Storm",
        "threat_type": "DEAUTH_STORM",
        "attacker_mac": "DE:AD:BE:EF:12:34",
        "target_mac": "FF:FF:FF:FF:FF:FF",
        "channel": 6,
        "rssi": -40,
        "packet_count": 300,
        "analysis": "Test deauth analysis",
        "mitigation": "1. Enforce 802.11w PMF\n2. Isolate MAC",
        "analyzed_at": "2026-08-18T12:00:00Z"
    })

    # JSON export
    json_res = client.get("/api/threats/export?format=json")
    assert json_res.status_code == 200
    json_data = json_res.json()
    assert "export_timestamp" in json_data
    assert "threats" in json_data
    assert len(json_data["threats"]) > 0

    # CSV export
    csv_res = client.get("/api/threats/export?format=csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    reader = csv.reader(io.StringIO(csv_res.text))
    rows = list(reader)
    assert len(rows) >= 2  # Header + at least 1 record
    assert rows[0] == ["Timestamp", "Threat Type", "Attacker MAC", "Target MAC", "Channel", "RSSI", "Analysis", "Mitigation"]

def test_clear_threats(client):
    clear_res = client.post("/api/threats/clear")
    assert clear_res.status_code == 200
    data = clear_res.json()
    assert data["success"] is True
    assert len(threat_history) == 0

def test_agent_chat_heuristics(client):
    # Test Deauth question fallback
    res1 = client.post("/api/agent/chat", json={"query": "How do I mitigate deauth attacks?", "context_threat_type": "DEAUTH_STORM"})
    assert res1.status_code == 200
    data1 = res1.json()
    assert "802.11w" in data1["response"] or "Deauthentication" in data1["response"] or "PMF" in data1["response"]
    assert "engine" in data1

    # Test Evil Twin fallback
    res2 = client.post("/api/agent/chat", json={"query": "What to do about an evil twin rogue AP?"})
    assert res2.status_code == 200
    data2 = res2.json()
    assert "Evil Twin" in data2["response"] or "WPA3" in data2["response"] or "802.1X" in data2["response"]

    # Test PMKID fallback
    res3 = client.post("/api/agent/chat", json={"query": "Explain PMKID hash sniffing."})
    assert res3.status_code == 200
    data3 = res3.json()
    assert "PMKID" in data3["response"] or "WPA3" in data3["response"]

    # Test ESP32 hardware query
    res4 = client.post("/api/agent/chat", json={"query": "Tell me about ESP32 hardware sniffer."})
    assert res4.status_code == 200
    data4 = res4.json()
    assert "ESP32-S3" in data4["response"] or "sniffer" in data4["response"]

def test_agent_models_and_set_model(client):
    # Get models
    res = client.get("/api/agent/models")
    assert res.status_code == 200
    data = res.json()
    assert "active_model" in data
    assert "default_model" in data
    assert "ollama_host" in data

    # Set active model
    set_res = client.post("/api/agent/set-model", json={"model": "qwen2.5-coder:7b"})
    assert set_res.status_code == 200
    set_data = set_res.json()
    assert set_data["success"] is True
    assert set_data["active_model"] == "qwen2.5-coder:7b"
    assert local_ai_engine.active_model == "qwen2.5-coder:7b"

    # Reset back to default
    client.post("/api/agent/set-model", json={"model": "llama3.2-vision:latest"})

def test_analyze_image_endpoint(client):
    # Dummy base64 string
    sample_b64 = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    res = client.post("/api/agent/analyze-image", json={
        "prompt": "Inspect RF spectrum plot",
        "image_b64": sample_b64
    })
    assert res.status_code == 200
    data = res.json()
    assert "analysis" in data
    assert "model" in data

def test_system_metrics(client):
    res = client.get("/api/system/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "cpu" in data
    assert "memory" in data
    assert "disk" in data
    assert "network_bytes_sent" in data
    assert "network_bytes_recv" in data
    assert "cores" in data

def test_devices_and_whitelist_and_block(client):
    # Get devices
    res = client.get("/api/devices")
    assert res.status_code == 200
    data = res.json()
    assert "gateway" in data
    assert "devices" in data
    assert len(data["devices"]) > 0

    # Whitelist new device
    whitelist_res = client.post("/api/devices/whitelist", json={
        "mac": "11:22:33:44:55:66",
        "name": "SecOps Test Laptop",
        "vendor": "Dell Inc.",
        "trusted": True,
        "rssi": -40
    })
    assert whitelist_res.status_code == 200
    wl_data = whitelist_res.json()
    assert wl_data["success"] is True
    assert wl_data["device"]["mac"] == "11:22:33:44:55:66"
    assert wl_data["device"]["trusted"] is True

    # Block device
    block_res = client.post("/api/devices/block?mac=11:22:33:44:55:66")
    assert block_res.status_code == 200
    blk_data = block_res.json()
    assert blk_data["success"] is True
    assert blk_data["device"]["trusted"] is False

def test_serial_endpoints(client):
    # List serial ports
    ports_res = client.get("/api/serial/ports")
    assert ports_res.status_code == 200
    data = ports_res.json()
    assert "available" in data
    assert "ports" in data
    assert "bridge_status" in data

    # Disconnect serial
    disc_res = client.post("/api/serial/disconnect")
    assert disc_res.status_code == 200
    assert disc_res.json()["success"] is True

def test_esp32_status(client):
    res = client.get("/api/esp32/status")
    assert res.status_code == 200
    data = res.json()
    assert "connected_ws" in data
    assert "connected_serial" in data
    assert "firmware_version" in data
    assert "voice_commands" in data
