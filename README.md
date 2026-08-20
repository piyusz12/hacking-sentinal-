# 🛡️ Project Sentinel: Edge AI Wireless Intrusion Detection System

**Enterprise-grade, air-gapped Wireless Intrusion Detection System (WIDS) powered by Edge Computing and Local Generative AI**

[![CI/CD](https://github.com/sentinel-wids/sentinel/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/sentinel-wids/sentinel/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/sentinel-wids/sentinel)](https://hub.docker.com/r/sentinel-wids/sentinel)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## 🚀 Overview

Project Sentinel bridges bare-metal hardware packet sniffing with modern Agentic AI workflows to detect, analyze, and mitigate Layer 2 IEEE 802.11 network attacks in real-time. Unlike traditional router firewalls (Layer 3/4), Sentinel operates directly at the Data Link Layer by manipulating Wi-Fi radio at the silicon level.

### Key Features

- **Edge Sensor**: ESP32-S3 with asymmetric dual-core processing for high-volume packet floods
- **Layer 2 Forensics**: Direct 802.11 frame parsing for deauthentication storms, probe floods, beacon spam
- **Air-Gapped AI**: Local Llama 3.2 Vision via Ollama - zero internet connectivity required
- **Real-Time Dashboard**: React SOC command center with sub-100ms updates
- **Multi-Sensory Feedback**: OLED display, piezo buzzer, RGB NeoPixel, I2S speaker alerts

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESP32-S3 Edge Sensor                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │  Core 0     │  │   Core 1     │  │  Hardware Peripherals │   │
│  │  Sniffer    │  │  Orchestrator│  │  - OLED SSD1306      │   │
│  │  ISR        │→ │  FreeRTOS    │→ │  - INMP441 Mic       │   │
│  │  (Promisc.) │  │  Event Loop  │  │  - MAX98357A DAC     │   │
│  └─────────────┘  └──────────────┘  │  - WS2812B RGB       │   │
│                                      │  - Piezo Buzzer      │   │
│                                      └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                            ↓ WebSocket
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend                              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │  WebSocket  │  │  LangGraph   │  │  FAISS Vector DB     │   │
│  │  Gateway    │→ │  AI Agent    │→ │  (Local Embeddings)  │   │
│  └─────────────┘  └──────────────┘  └──────────────────────┘   │
│         ↓                ↓                                       │
│  ┌─────────────┐  ┌──────────────┐                              │
│  │  Ollama     │  │  Threat      │                              │
│  │  (Llama 3.2)│  │  History DB  │                              │
│  └─────────────┘  └──────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
                            ↓ REST API + WebSocket
┌─────────────────────────────────────────────────────────────────┐
│                  React SOC Dashboard                            │
│  - Real-time telemetry graphs                                   │
│  - AI analysis streaming panel                                  │
│  - Device management (block/whitelist)                          │
│  - Threat simulation controls                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| **Air-Gapped AI** | Zero data exfiltration - all analysis runs locally |
| **Secure Tokens** | Auto-generated cryptographically secure tokens |
| **Rate Limiting** | Configurable per-endpoint rate limits |
| **Input Validation** | Strict MAC address regex, hex validation |
| **CORS Hardening** | Whitelist-only origins (no wildcards) |
| **Authentication** | JWT-based auth on critical endpoints |

---

## 📦 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker & Docker Compose (optional)
- Ollama with `llama3.2` and `llama3.2-vision` models
- ESP32-S3 board (for hardware mode)

### Option 1: Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/sentinel-wids/sentinel.git
cd sentinel

# Copy environment file
cp .env.example .env

# Edit .env with your secure tokens
nano .env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f backend
```

### Option 2: Manual Installation

```bash
# Backend setup
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend setup
cd sentinel-ui
npm install
npm run build

# Start Ollama (separate terminal)
ollama serve

# Pull models
ollama pull llama3.2
ollama pull llama3.2-vision

# Start backend
uvicorn backend_server.main:app --reload

# Start frontend (separate terminal)
cd sentinel-ui
npm run dev
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_ENV` | `development` | Environment (development/production) |
| `SENTINEL_WS_TOKEN` | auto-generated | WebSocket authentication token |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |
| `SENTINEL_MAX_DASHBOARD` | `50` | Max WebSocket dashboard clients |
| `SENTINEL_DEAUTH_THRESHOLD` | `5` | Deauth packets/sec threshold |

See `.env.example` for all configuration options.

---

## 📡 API Endpoints

### Threat Detection

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/threats/alert` | POST | Receive threat alert from ESP32 |
| `/api/threats/simulate` | POST | Simulate network attack |
| `/api/threats` | GET | Get threat history |
| `/api/threats/{id}` | GET | Get specific threat details |
| `/api/threats` | DELETE | Clear threat history |

### AI Agent

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/agent/chat` | POST | Chat with AI security analyst |
| `/api/agent/analyze` | POST | Analyze specific threat |
| `/api/agent/models` | GET | List available AI models |

### Device Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List all devices |
| `/api/devices/block` | POST | Block device by MAC |
| `/api/devices/whitelist` | POST | Whitelist trusted device |

### System

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/stats` | GET | System statistics |
| `/docs` | GET | Swagger API documentation |

---

## 🧪 Testing

```bash
# Run backend tests
pytest tests/ --cov=backend_server --cov-report=html

# Run frontend tests
cd sentinel-ui
npm test -- --coverage

# Security scanning
bandit -r backend_server
npm audit --prefix sentinel-ui
```

---

## 📊 Performance Benchmarks

| Metric | Value |
|--------|-------|
| Packet Processing | 10,000+ pkt/sec |
| AI Response Time | < 2s (local) |
| WebSocket Latency | < 100ms |
| False Positive Rate | < 1% |
| Memory Usage | ~500MB |

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Espressif Systems for ESP32-S3
- Ollama team for local LLM infrastructure
- LangChain/LangGraph for agent workflows
- FastAPI community for async web framework

---

## 📞 Support

- Documentation: https://sentinel-wids.github.io/docs
- Issues: https://github.com/sentinel-wids/sentinel/issues
- Discussions: https://github.com/sentinel-wids/sentinel/discussions

---

**Built with ❤️ for cybersecurity professionals**
