# 🛡️ Sentinel DevSecOps & Wi-Fi IDS AI Platform v3.5

Sentinel is an enterprise-grade, real-time wireless threat intelligence and DevSecOps monitoring system. It pairs an **ESP32-S3 hardware sniffer** (or high-fidelity threat simulator) with a **FastAPI backend**, **LangGraph Local AI security analyst** powered by **Ollama (`llama3.2-vision:latest`)**, **FAISS vector database**, and a **sleek React SOC command dashboard**.

---

## 🦙 100% Local & Offline AI Architecture

Sentinel v3.5 runs **100% locally and offline** without requiring external cloud API keys (e.g. OpenAI):
- **Primary AI Model**: `llama3.2-vision:latest` (or local Ollama models)
- **Local AI Provider**: [Ollama](https://ollama.com) running at `http://localhost:11434`
- **Multi-Model Resiliency**: Automatically cascades across available local models (`llama3.2-vision:latest`, `llama3.2:latest`, `llama3.1:latest`, `qwen2.5-coder:7b`, `deepseek-r1:8b`) and the built-in forensic rules engine for zero downtime.
- **Multimodal Vision Analysis**: Capable of inspecting visual RF spectrum spectrograms, packet distribution plots, and network topology diagrams.

---

## 🚀 Quickstart (One-Click Launch)

### Option A: Windows 1-Click Batch Launcher
Double-click:
```cmd
start_sentinel.bat
```
*This automatically starts both the FastAPI backend on port `8000` and the React Vite UI on port `5173`.*

---

### Option B: Manual Command Line Launch

#### 1. Start Ollama (if not already running):
```bash
ollama serve
```

#### 2. Start the Backend Server (FastAPI + LangGraph Local AI + WebSockets):
```bash
python main.py
# or
uvicorn backend_server.main:app --host 0.0.0.0 --port 8000 --reload
```
- **API Root**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Dashboard WebSocket**: `ws://localhost:8000/ws/dashboard`
- **ESP32 Telemetry WebSocket**: `ws://localhost:8000/ws/esp32`

#### 3. Start the Frontend Dashboard (React + Vite):
```bash
cd sentinel-ui
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## ⚡ Core Features

### 1. 🤖 LangGraph Local AI SOC Analyst & Forensic Deck
- Ingests real-time 802.11 management frame telemetry (0x0C Deauth, 0x08 Beacon, 0x04 Probe, Rogue APs, Karma exploits, PMKID captures).
- Automatically queries the embedded **FAISS Vector DB** for exact threat heuristics.
- Compiles tactical **DevSecOps mitigation playbooks** (e.g. 802.11w PMF enforcement, BSSID cryptographic verification, channel hopping).
- Interactive conversational AI Analyst tab to query security guidance directly via local Ollama models.

### 2. 🎯 Interactive Threat Simulation Sandbox
- Test and demonstrate the full system instantly with 1-click presets:
  - **0x0C Deauth Storm**: Continuous management deauth flood.
  - **Evil Twin Rogue AP**: Spoofed BSSID beacon injection for credential harvesting.
  - **0x08 Beacon Flood**: Wireless stack exhaustion attack.
  - **0x04 Probe Recon Burst**: RF station fingerprint mapping.
  - **KARMA PNL Hijack**: Preferred network list Coercion.
  - **PMKID Hash Sniff**: 4-way handshake EAPOL frame 1 capture.
- Custom parameter sliders (MAC address, Channel 1-14, RSSI, Packet Rate).

### 3. 🔌 Physical ESP32 Hardware Integration
- **Dual-Core Architecture**:
  - **Core 0**: Promiscuous 802.11 sniffer with zero frame drops.
  - **Core 1**: SSD1306 OLED display + INMP441 I2S microphone clap voice detection.
    - *1 Clap*: Scan Networks
    - *2 Claps*: Stop All Attacks
    - *3 Claps*: Show Hardware Stats
- **Serial Bridge**: Connect ESP32 via USB (e.g. `COM3`) using the UI or standalone `python serial_bridge.py`.

### 4. 🌐 Real-Time 802.11 RF Topology & Security Radar
- Interactive graphical RF association map showing Access Point, trusted stations, and live glowing rogue nodes.
- Device MAC Whitelist Registry with 1-click Trust/Block controls.

---

## 📡 API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | System status, local AI configuration, version, uptime |
| `GET` | `/health` | Health diagnostics, local AI engine name, and host telemetry |
| `GET` | `/api/stats` | Real-time packet throughput, threat tally, connection metrics |
| `GET` | `/api/threats` | Filtered historical threat incidents |
| `GET` | `/api/threats/export` | Download threat logs as CSV or JSON |
| `POST` | `/api/threats/simulate` | Dispatch simulated 802.11 threat to Local AI pipeline |
| `POST` | `/api/threats/clear` | Clear active incident state and threat history |
| `POST` | `/api/agent/chat` | Query Sentinel AI DevSecOps security analyst (Local Ollama) |
| `POST` | `/api/agent/analyze-image` | Multimodal RF spectrum / diagram vision analysis |
| `GET` | `/api/agent/models` | List all discovered local Ollama models and active status |
| `POST` | `/api/agent/set-model` | Select active local model (e.g. `llama3.2-vision:latest`) |
| `GET` | `/api/system/metrics` | Host CPU, RAM, Disk, and Network telemetry |
| `GET` | `/api/devices` | Connected station inventory & whitelist table |
| `POST` | `/api/devices/whitelist` | Add or trust a station MAC address |
| `POST` | `/api/devices/block` | Quarantine and block a rogue transmitter |
| `GET` | `/api/serial/ports` | List available host COM ports |
| `POST` | `/api/serial/connect` | Start background USB serial reader |
| `POST` | `/api/serial/disconnect` | Stop background serial reader |
| `WS` | `/ws/dashboard` | WebSocket stream for React SOC Dashboard |
| `WS` | `/ws/esp32` | WebSocket ingestion for physical ESP32 sensors |

---

## 📂 Project Architecture

```
sentinel-server/
├── backend_server/
│   ├── __init__.py
│   └── main.py              # FastAPI server + LangGraph Local AI + WebSockets
├── sentinel-ui/             # React Vite SOC Command Dashboard
│   ├── src/
│   │   ├── App.jsx          # Full interactive dashboard interface
│   │   └── index.css        # Premium dark cybersecurity theme
│   └── package.json
├── sentinal-v2/
│   └── sentinal-v2.ino      # Dual-Core ESP32-S3 sniffer firmware
├── main.py                  # Direct entrypoint for backend
├── run_backend.py           # Backend launcher helper
├── serial_bridge.py         # Standalone USB Serial to WebSocket bridge
└── start_sentinel.bat       # Windows 1-click launcher
```
