import os
import json
import re
import pytest

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def test_frontend_package_json():
    pkg_path = os.path.join(WORKSPACE_ROOT, "sentinel-ui", "package.json")
    assert os.path.exists(pkg_path), "sentinel-ui/package.json missing"
    
    with open(pkg_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)
    
    assert pkg["name"] == "sentinel-ui"
    assert "scripts" in pkg
    assert "dev" in pkg["scripts"]
    assert "build" in pkg["scripts"]
    assert "lint" in pkg["scripts"]
    assert "lucide-react" in pkg["dependencies"]
    assert "recharts" in pkg["dependencies"]
    assert "react" in pkg["dependencies"]

def test_frontend_app_jsx_integrity():
    app_jsx_path = os.path.join(WORKSPACE_ROOT, "sentinel-ui", "src", "App.jsx")
    assert os.path.exists(app_jsx_path), "App.jsx missing"
    
    with open(app_jsx_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Check that presets align with backend threat types
    expected_threats = [
        "DEAUTH_STORM",
        "EVIL_TWIN",
        "BEACON_FLOOD",
        "PROBE_STORM",
        "KARMA_ATTACK",
        "PMKID_CAPTURE"
    ]
    for threat in expected_threats:
        assert threat in content, f"Threat preset {threat} missing in App.jsx"

    # Check WebSocket connection logic
    assert "ws://localhost:8000" in content or "VITE_WS_URL" in content
    assert "sentinel-dev-token-change-me" in content or "VITE_WS_TOKEN" in content

def test_frontend_index_css():
    css_path = os.path.join(WORKSPACE_ROOT, "sentinel-ui", "src", "index.css")
    assert os.path.exists(css_path), "index.css missing"
    
    with open(css_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert len(content) > 1000, "index.css appears incomplete"
    assert "font-family" in content

def test_firmware_ino_structure():
    ino_path = os.path.join(WORKSPACE_ROOT, "sentinal-v2", "sentinal-v2.ino")
    assert os.path.exists(ino_path), "sentinal-v2.ino missing"
    
    with open(ino_path, "r", encoding="utf-8") as f:
        code = f.read()
    
    # Required headers
    headers = [
        "#include <WiFi.h>",
        "#include <WebServer.h>",
        "#include <DNSServer.h>",
        "#include <esp_wifi.h>",
        "#include <Adafruit_SSD1306.h>",
        "#include <driver/i2s.h>"
    ]
    for h in headers:
        assert h in code, f"Header {h} missing in sentinal-v2.ino"

    # Verify pin configuration
    assert "#define OLED_SDA" in code
    assert "#define OLED_SCL" in code
    assert "#define I2S_WS" in code
    assert "#define I2S_SCK" in code
    assert "#define I2S_SD" in code

    # Verify clap / voice command configuration
    assert "CLAP_THRESHOLD" in code
    assert "CLAP_DEBOUNCE_MS" in code
    assert "CLAP_WINDOW_MS" in code

    # Verify setup and loop functions
    assert "void setup()" in code
    assert "void loop()" in code
