import pytest
from fastapi.testclient import TestClient
from backend_server.main import app
from backend_server.frame_parser import decode_80211_frame, FrameRingBufferPython

@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client

def test_decode_deauth_frame():
    # 802.11 Deauth Frame (FC: 0x00C0, Addr1: FF:FF:FF:FF:FF:FF, Addr2: DE:AD:BE:EF:00:01, Addr3: DE:AD:BE:EF:00:01, Seq: 0x0000, Reason: 0x0007)
    deauth_hex = "c0003a01ffffffffffffdeadbeef0001deadbeef000100000700"
    raw_bytes = bytes.fromhex(deauth_hex)
    result = decode_80211_frame(raw_bytes)

    assert result["valid"] is True
    assert result["frame_type"] == 0  # Management
    assert result["frame_subtype"] == 12  # 0x0C (Deauth)
    assert result["threat_classification"] == "DEAUTH_STORM"
    assert result["is_threat"] is True
    assert result["threat_severity"] == 5
    assert result["receiver_mac"] == "FF:FF:FF:FF:FF:FF"
    assert result["transmitter_mac"] == "DE:AD:BE:EF:00:01"

def test_decode_beacon_frame():
    # 802.11 Beacon Frame (FC: 0x0080)
    beacon_hex = "80000000ffffffffffff0011223344550011223344551000"
    raw_bytes = bytes.fromhex(beacon_hex)
    result = decode_80211_frame(raw_bytes)

    assert result["valid"] is True
    assert result["frame_type"] == 0
    assert result["frame_subtype"] == 8  # 0x08 (Beacon)
    assert result["threat_classification"] == "BEACON_FRAME"
    assert result["transmitter_mac"] == "00:11:22:33:44:55"

def test_decode_probe_request_frame():
    # 802.11 Probe Request (FC: 0x0040)
    probe_hex = "40000000ffffffffffffaa11bb22cc33ffffffffffff2000"
    raw_bytes = bytes.fromhex(probe_hex)
    result = decode_80211_frame(raw_bytes)

    assert result["valid"] is True
    assert result["frame_type"] == 0
    assert result["frame_subtype"] == 4  # 0x04 (Probe Req)
    assert result["threat_classification"] == "PROBE_REQUEST"
    assert result["transmitter_mac"] == "AA:11:BB:22:CC:33"

def test_decode_short_frame():
    short_bytes = b"\x00\x01\x02"
    result = decode_80211_frame(short_bytes)
    assert result["valid"] is False
    assert "too short" in result["error"]

def test_ring_buffer_operations():
    rb = FrameRingBufferPython(capacity=4)
    assert rb.count() == 0

    # Push items
    assert rb.push(b"pkt1") is True
    assert rb.push(b"pkt2") is True
    assert rb.push(b"pkt3") is True
    assert rb.count() == 3

    # Buffer full on capacity 4 (tail-1)
    assert rb.push(b"pkt4_dropped") is False
    assert rb.dropped_frames == 1

    # Pop item
    item, ts = rb.pop()
    assert item == b"pkt1"
    assert rb.count() == 2

def test_parse_raw_endpoint(client):
    deauth_hex = "c0003a01ffffffffffffdeadbeef0001deadbeef000100000700"
    res = client.post("/api/frames/parse-raw", json={
        "frame_hex": deauth_hex,
        "sensor_id": "TEST-SNIFFER",
        "channel": 6,
        "rssi": -45
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["is_threat"] is True
    assert data["threat_classification"] == "DEAUTH_STORM"
    assert data["parsed"]["transmitter_mac"] == "DE:AD:BE:EF:00:01"
