import json
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from backend_server.main import app, manager, ConnectionManager

@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client

def test_dashboard_ws_valid_token_and_ack(client):
    with client.websocket_connect("/ws/dashboard?token=sentinel-dev-token-change-me") as ws:
        ack = ws.receive_json()
        assert ack["type"] == "connection_ack"
        assert "Sentinel DevSecOps AI Guardian Backend" in ack["message"]

def test_dashboard_ws_invalid_token(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/dashboard?token=WRONG_TOKEN_VALUE") as ws:
            ws.receive_json()

def test_dashboard_ws_ping_pong(client):
    with client.websocket_connect("/ws/dashboard") as ws:
        # receive initial ack
        ws.receive_json()
        # send ping
        ws.send_text("ping")
        resp = ws.receive_text()
        assert resp == "pong"

def test_dashboard_ws_threat_dispatch_and_broadcast(client):
    with client.websocket_connect("/ws/dashboard") as ws1:
        with client.websocket_connect("/ws/dashboard") as ws2:
            # Drain ack
            ws1.receive_json()
            ws2.receive_json()

            # ws1 sends simulated threat payload
            test_payload = {
                "threat_type": "PROBE_STORM",
                "attacker_mac": "8C:3B:AD:77:88:99",
                "channel": 11,
                "rssi": -58,
                "packet_count": 640
            }
            ws1.send_text(json.dumps(test_payload))

            # Both ws1 and ws2 should receive raw_alert broadcast
            msg1 = ws1.receive_json()
            msg2 = ws2.receive_json()
            assert msg1["type"] == "raw_alert"
            assert msg2["type"] == "raw_alert"
            assert msg1["data"]["threat_type"] == "PROBE_STORM"
            assert msg2["data"]["attacker_mac"] == "8C:3B:AD:77:88:99"

def test_esp32_ws_voice_command_forwarding(client):
    with client.websocket_connect("/ws/dashboard") as dash_ws:
        dash_ws.receive_json() # ack

        with client.websocket_connect("/ws/esp32?token=sentinel-dev-token-change-me") as esp_ws:
            # ESP32 sends voice event
            voice_payload = {
                "type": "voice_command",
                "command": "Scan Networks",
                "claps": 1
            }
            esp_ws.send_text(json.dumps(voice_payload))

            # Dashboard receives voice event
            dash_msg = dash_ws.receive_json()
            assert dash_msg["type"] == "esp32_voice_event"
            assert dash_msg["command"] == "Scan Networks"
            assert dash_msg["claps"] == 1

def test_esp32_ws_threat_ingestion(client):
    with client.websocket_connect("/ws/dashboard") as dash_ws:
        dash_ws.receive_json() # ack

        with client.websocket_connect("/ws/esp32") as esp_ws:
            threat_payload = {
                "threat_type": "BEACON_FLOOD",
                "attacker_mac": "AA:11:BB:22:CC:33",
                "channel": 1,
                "rssi": -48,
                "packet_count": 3200
            }
            esp_ws.send_text(json.dumps(threat_payload))

            dash_msg = dash_ws.receive_json()
            assert dash_msg["type"] == "raw_alert"
            assert dash_msg["data"]["threat_type"] == "BEACON_FLOOD"

def test_esp32_ws_invalid_payload(client):
    with client.websocket_connect("/ws/esp32") as esp_ws:
        # Send invalid JSON
        esp_ws.send_text("THIS IS NOT JSON")
        err = esp_ws.receive_json()
        assert "error" in err
        assert "Invalid JSON" in err["error"] or "Validation failed" in err["error"]

def test_esp32_ws_oversized_payload(client):
    with client.websocket_connect("/ws/esp32") as esp_ws:
        huge_payload = "A" * 15000
        esp_ws.send_text(huge_payload)
        err = esp_ws.receive_json()
        assert "error" in err
        assert err["error"] == "Payload too large"

def test_sentinel_v3_ws_online_and_telemetry(client):
    with client.websocket_connect("/ws/dashboard") as dash_ws:
        dash_ws.receive_json() # ack

        with client.websocket_connect("/ws/sentinel") as sent_ws:
            # 1. Send sentinel_online
            sent_ws.send_text(json.dumps({"event": "sentinel_online", "version": "3.0"}))
            status_msg = dash_ws.receive_json()
            assert status_msg["type"] == "esp32_status"
            assert status_msg["status"] == "online"
            assert status_msg["version"] == "3.0"

            # 2. Send telemetry
            sent_ws.send_text(json.dumps({
                "event": "telemetry",
                "pkt_rate": 240,
                "mgmt_frames": 180,
                "data_frames": 60,
                "channel": 6,
                "wifi_rssi": -45,
                "heap_free": 240000,
                "timestamp": 123456
            }))
            telem_msg = dash_ws.receive_json()
            assert telem_msg["type"] == "esp32_telemetry"
            assert telem_msg["data"]["pkt_rate"] == 240

def test_sentinel_v3_threat_detected_event(client):
    with client.websocket_connect("/ws/dashboard") as dash_ws:
        dash_ws.receive_json() # ack

        with client.websocket_connect("/ws/sentinel") as sent_ws:
            sent_ws.send_text(json.dumps({
                "event": "threat_detected",
                "type": "DEAUTH_FLOOD",
                "mac": "11:22:33:44:55:66",
                "rssi": -42,
                "channel": 6,
                "count": 15,
                "timestamp": 123456
            }))
            alert_msg = dash_ws.receive_json()
            assert alert_msg["type"] == "raw_alert"
            assert alert_msg["data"]["threat_type"] == "DEAUTH_FLOOD"
            assert alert_msg["data"]["attacker_mac"] == "11:22:33:44:55:66"

def test_connection_manager_limits():
    test_mgr = ConnectionManager(max_dashboard=2, max_esp32=1)
    assert test_mgr._max_dashboard == 2
    assert test_mgr._max_esp32 == 1
    assert len(test_mgr.dashboard_clients) == 0
    assert len(test_mgr.esp32_clients) == 0
