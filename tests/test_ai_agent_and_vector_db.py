import pytest
import asyncio
import backend_server.main as bsm

@pytest.mark.asyncio
async def test_vector_db_initialization_and_retrieval():
    bsm.init_vector_database()
    assert bsm.vector_db is not None
    
    # Test similarity retrieval for Deauth
    state = {
        "threat_payload": {"threat_type": "DEAUTH_STORM"},
        "historical_context": "",
        "ai_analysis": "",
        "mitigation_steps": ""
    }
    res = bsm.retrieve_context(state)
    assert "historical_context" in res
    assert len(res["historical_context"]) > 10
    assert any(res["historical_context"] == v for v in bsm.KNOWLEDGE_VECTORS) or "802.11" in res["historical_context"]

@pytest.mark.asyncio
async def test_analyze_threat_node_heuristics():
    # Test all known threat signatures
    threat_types = [
        ("DEAUTH_STORM", "Deauthentication"),
        ("EVIL_TWIN", "Beacon"),
        ("BEACON_FLOOD", "Beacon"),
        ("PROBE_STORM", "Probe"),
        ("KARMA_ATTACK", "KARMA"),
        ("PMKID_CAPTURE", "EAPOL"),
        ("WPS_BRUTE_FORCE", "WPS"),
        ("UNKNOWN_ANOMALY", "Anomalous")
    ]

    for ttype, expected_keyword in threat_types:
        state = {
            "threat_payload": {
                "threat_type": ttype,
                "attacker_mac": "DE:AD:BE:EF:11:22",
                "target_mac": "FF:FF:FF:FF:FF:FF",
                "channel": 6,
                "rssi": -45,
                "packet_count": 200
            },
            "historical_context": "Test signature context",
            "ai_analysis": "",
            "mitigation_steps": ""
        }
        out = await bsm.analyze_threat_node(state)
        assert "ai_analysis" in out
        assert expected_keyword.lower() in out["ai_analysis"].lower()

@pytest.mark.asyncio
async def test_generate_mitigation_node_heuristics():
    threat_types = [
        ("DEAUTH_STORM", "802.11w"),
        ("EVIL_TWIN", "BSSID"),
        ("BEACON_FLOOD", "Dynamic Channel Selection"),
        ("PROBE_STORM", "SSID"),
        ("PMKID_CAPTURE", "WPA3"),
        ("KARMA_ATTACK", "auto-connect"),
        ("CUSTOM_ANOMALY", "PCAP")
    ]

    for ttype, expected_keyword in threat_types:
        state = {
            "threat_payload": {
                "threat_type": ttype,
                "attacker_mac": "AA:BB:CC:DD:EE:01",
                "channel": 6
            },
            "historical_context": "",
            "ai_analysis": "Diagnostic summary",
            "mitigation_steps": ""
        }
        out = await bsm.generate_mitigation_node(state)
        assert "mitigation_steps" in out
        assert expected_keyword.lower() in out["mitigation_steps"].lower()

@pytest.mark.asyncio
async def test_langgraph_compilation_and_pipeline():
    bsm.compile_langgraph_agent()
    
    # Run full AI pipeline on a sample threat
    payload = {
        "sensor_id": "TEST_UNIT_SENSOR",
        "threat_type": "KARMA_ATTACK",
        "attacker_mac": "F0:DE:F1:22:33:44",
        "target_mac": "FF:FF:FF:FF:FF:FF",
        "channel": 6,
        "rssi": -38,
        "packet_count": 810
    }
    
    initial_history_len = len(bsm.threat_history)
    await bsm.run_ai_pipeline(payload)
    
    assert len(bsm.threat_history) >= initial_history_len + 1
    latest_report = bsm.threat_history[0]
    assert latest_report["type"] == "ai_report"
    assert latest_report["threat_type"] == "KARMA_ATTACK"
    assert "KARMA" in latest_report["analysis"]
    assert "auto-connect" in latest_report["mitigation"].lower() or "mdm" in latest_report["mitigation"].lower()

    # Check that rogue device was automatically registered/updated in device registry
    found_rogue = any(d["mac"] == "F0:DE:F1:22:33:44" and d["trusted"] is False for d in bsm.devices_registry)
    assert found_rogue is True

@pytest.mark.asyncio
async def test_local_ollama_engine_helpers():
    engine = bsm.LocalOllamaEngine(host="http://localhost:11434")
    assert engine.default_model == "llama3.2-vision:latest"
    assert engine.active_model == "llama3.2-vision:latest"
    
    # Test base64 image telemetry processing with data URI header
    res = await engine.analyze_image_telemetry(
        "Analyze spectrogram",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
    )
    assert isinstance(res, dict)
    assert "response" in res
