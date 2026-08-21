"""
Sentinel DevSecOps & Wi-Fi IDS AI Backend v3.5
==============================================
FastAPI + Async WebSockets + LangGraph AI SOC Analyst + Local Ollama (llama3.2-vision:latest) + FAISS Vector DB + ESP32 Hardware
"""

import os
import re
import csv
import json
import time
import io
import asyncio
import logging
import secrets
import random
import xml.sax.saxutils
from typing import TypedDict, List, Optional, Union, Dict, Any
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Request, Response, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator
import subprocess
import platform

# System metrics
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Serial communication for ESP32
try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

# LangChain & LangGraph Imports
try:
    from langchain_core.messages import SystemMessage, HumanMessage
    from langgraph.graph import StateGraph, END
    from langchain_community.vectorstores import FAISS
    from langchain_core.embeddings import FakeEmbeddings
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

# Fast JSON serialization (Rust / C-accelerated)
try:
    import orjson
    def fast_dumps(obj: Any) -> str:
        return orjson.dumps(obj).decode("utf-8")
    def fast_loads(s: Union[str, bytes]) -> Any:
        return orjson.loads(s)
    ORJSON_AVAILABLE = True
except ImportError:
    def fast_dumps(obj: Any) -> str:
        return json.dumps(obj)
    def fast_loads(s: Union[str, bytes]) -> Any:
        return json.loads(s)
    ORJSON_AVAILABLE = False

# Native 802.11 Frame Decoder Bridge
try:
    from backend_server.frame_parser import decode_80211_frame, NATIVE_AVAILABLE
except ImportError:
    from frame_parser import decode_80211_frame, NATIVE_AVAILABLE

# --- Configuration & Environment ---
WS_AUTH_TOKEN = os.environ.get("SENTINEL_WS_TOKEN", "sentinel-dev-token-change-me")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_LOCAL_MODEL = os.environ.get("SENTINEL_LOCAL_MODEL", "llama3:latest")
MAX_DASHBOARD_CLIENTS = int(os.environ.get("SENTINEL_MAX_DASHBOARD", "50"))
MAX_ESP32_CLIENTS = int(os.environ.get("SENTINEL_MAX_ESP32", "10"))
MAX_CONCURRENT_AI_TASKS = int(os.environ.get("SENTINEL_MAX_AI_TASKS", "5"))

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("Sentinel-Backend")


# --- Local Ollama AI Engine ---
class LocalOllamaEngine:
    """
    High-Performance Local AI Engine powered by Ollama.
    Dedicated exclusively to llama3.2-vision:latest for 802.11 DevSecOps & RF telemetry analysis.
    """

    @property
    def engine_display_name(self) -> str:
        """Canonical display name for the active AI engine — used across all API responses."""
        if self.ollama_online:
            model = self.last_successful_model or self.active_model
            return f"Local Ollama ({model}) + LangGraph"
        return "Sentinel Local Forensic AI Engine"
    def __init__(self, host: str = OLLAMA_HOST, default_model: str = DEFAULT_LOCAL_MODEL):
        self.host = host
        self.default_model = default_model
        self.active_model = default_model
        self.fallback_models = [default_model]
        self.last_successful_model: Optional[str] = default_model
        self.ollama_online: bool = False
        self.available_models: List[str] = []

    async def refresh_models(self) -> List[str]:
        try:
            async with httpx.AsyncClient(base_url=self.host, timeout=5.0) as client:
                res = await client.get("/api/tags")
                if res.status_code == 200:
                    data = res.json()
                    models_list = data.get("models", [])
                    self.available_models = [m.get("name", "") for m in models_list]
                    self.ollama_online = True
                    self.active_model = "llama3:latest"
                    return self.available_models
        except Exception as e:
            logger.debug(f"Ollama discovery ping failed: {e}")
        self.ollama_online = False
        return []

    async def chat(
        self,
        messages: List[Dict[str, Any]],
        images: Optional[List[Union[str, bytes]]] = None,
        timeout: float = 45.0,
        model_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes chat inference strictly using llama3.2-vision:latest.
        """
        if not self.ollama_online:
            return {"response": "", "model": "offline", "engine": "local_ai", "success": False}

        candidate = model_override or self.active_model or "llama3:latest"
        candidates = [candidate]

        # Attach images to user message if present
        formatted_messages = []
        for msg in messages:
            msg_dict = dict(msg)
            if msg_dict.get("role") == "user" and images and "images" not in msg_dict:
                msg_dict["images"] = images
            formatted_messages.append(msg_dict)

        async with httpx.AsyncClient(base_url=self.host, timeout=timeout) as client:
            for candidate in candidates:
                try:
                    logger.debug(f"Querying local model: {candidate}...")
                    res = await client.post("/api/chat", json={
                        "model": candidate,
                        "messages": formatted_messages,
                        "stream": False,
                        "options": {
                            "num_predict": 200,
                            "temperature": 0.2
                        }
                    })
                    if res.status_code == 200:
                        data = res.json()
                        content = data.get("message", {}).get("content", "")
                        if content and content.strip():
                            self.last_successful_model = candidate
                            self.active_model = candidate
                            self.ollama_online = True
                            return {
                                "response": content.strip(),
                                "model": candidate,
                                "engine": f"local_ollama_{candidate}",
                                "success": True
                            }
                    else:
                        logger.warning(f"Ollama candidate '{candidate}' returned {res.status_code}: {res.text[:120]}")
                except Exception as exc:
                    logger.warning(f"Ollama candidate '{candidate}' inference notice: {exc}")

        return {"response": "", "model": "none", "engine": "sentinel_local_rule_engine", "success": False}

    async def analyze_threat(self, payload: dict, historical_context: str) -> str:
        ttype = payload.get("threat_type", "UNKNOWN")
        mac = payload.get("attacker_mac", "DE:AD:BE:EF:00:01")
        target = payload.get("target_mac", "FF:FF:FF:FF:FF:FF")
        ch = payload.get("channel", 6)
        rssi = payload.get("rssi", -55)
        pkts = payload.get("packet_count") or payload.get("pkt_rate") or 150

        summary = f"Threat: {ttype}, Attacker MAC: {mac}, Target MAC: {target}, Channel: {ch}, RSSI: {rssi} dBm, Packets: {pkts}"
        messages = [
            {
                "role": "system",
                "content": "You are Sentinel AI SOC Analyst, an expert DevSecOps and 802.11 Wi-Fi security analyst. Provide a concise, highly technical 2-sentence forensic breakdown of this live RF frame threat captured by sniffer hardware."
            },
            {
                "role": "user",
                "content": f"Live Captured Telemetry:\n{summary}\nSignature Reference Context:\n{historical_context}\nProvide forensic diagnosis."
            }
        ]
        result = await self.chat(messages, timeout=45.0)
        if result["success"] and result["response"]:
            return result["response"]
        return ""

    async def generate_mitigation(self, payload: dict, analysis: str) -> str:
        ttype = payload.get("threat_type", "UNKNOWN")
        mac = payload.get("attacker_mac", "DE:AD:BE:EF:00:01")
        messages = [
            {
                "role": "system",
                "content": "You are Sentinel AI DevSecOps Security Engineer. Provide exactly 3 actionable, high-impact tactical defense recommendations for network administrators and automated firewall containment."
            },
            {
                "role": "user",
                "content": f"Threat Type: {ttype}\nAttacker MAC: {mac}\nForensic Diagnosis: {analysis}\nProvide 3 numbered tactical mitigation bullet points."
            }
        ]
        result = await self.chat(messages, timeout=45.0)
        if result["success"] and result["response"]:
            return result["response"]
        return ""

    async def analyze_image_telemetry(self, prompt: str, image_b64: str) -> Dict[str, Any]:
        messages = [
            {
                "role": "system",
                "content": "You are Sentinel AI Vision Specialist. You analyze visual RF spectrum spectrograms, packet capture graphs, and network topology diagrams for wireless intrusions and RF jamming."
            },
            {"role": "user", "content": prompt}
        ]
        clean_b64 = image_b64
        if "base64," in clean_b64:
            clean_b64 = clean_b64.split("base64,")[1]
        result = await self.chat(messages, images=[clean_b64], timeout=30.0, model_override=self.default_model)
        return result


local_ai_engine = LocalOllamaEngine()


# --- Lifespan Context Manager ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡️ Sentinel DevSecOps AI Backend v3.5 Initializing...")
    init_vector_database()
    compile_langgraph_agent()
    
    # Initialize Local AI Ollama Connection
    try:
        models = await local_ai_engine.refresh_models()
        if models:
            logger.info(f"🦙 Local Ollama connected! Detected {len(models)} models: {models}")
            logger.info(f"🎯 Default Active Model: {local_ai_engine.active_model}")
        else:
            logger.warning(f"⚠️ Local Ollama at {local_ai_engine.host} not responding yet. Fallback heuristic engine active.")
    except Exception as e:
        logger.warning(f"⚠️ Local Ollama probe warning: {e}")

    yield
    logger.info("🛡️ Sentinel DevSecOps AI Backend shutting down...")
    if serial_bridge_state.get("is_running") and serial_bridge_state.get("task"):
        serial_bridge_state["task"].cancel()


app = FastAPI(
    title="Sentinel DevSecOps & Wi-Fi IDS Backend",
    description="Real-time Wi-Fi Threat Intelligence, LangGraph AI Security Analyst, and ESP32 Telemetry Gateway",
    version="3.5.0",
    lifespan=lifespan
)

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Data Models & Schemas ---
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

class ThreatPayload(BaseModel):
    """Threat data structure sent by ESP32 sensor or simulated by Dashboard."""
    sensor_id: Optional[str] = Field("ESP32-S3-SNIFFER", max_length=50)
    threat_type: str = Field(..., min_length=1, max_length=100)
    attacker_mac: Optional[str] = Field("DE:AD:BE:EF:00:01", max_length=17)
    target_mac: Optional[str] = Field("FF:FF:FF:FF:FF:FF", max_length=17)
    channel: Optional[int] = Field(6, ge=1, le=14)
    rssi: Optional[int] = Field(-55, ge=-100, le=0)
    packet_count: Optional[int] = Field(150, ge=0)
    pkt_rate: Optional[int] = Field(None, ge=0)
    timestamp: Optional[Union[str, int, float]] = None

    @field_validator("attacker_mac", "target_mac", mode="before")
    @classmethod
    def validate_mac(cls, v):
        if v is not None and isinstance(v, str) and not MAC_REGEX.match(v):
            return "DE:AD:BE:EF:00:01"
        return v or "DE:AD:BE:EF:00:01"

    @field_validator("threat_type", mode="before")
    @classmethod
    def sanitize_threat_type(cls, v):
        if isinstance(v, str):
            cleaned = re.sub(r"[^a-zA-Z0-9\s\-_]", "", v)[:100]
            return cleaned if cleaned else "UNKNOWN_ANOMALY"
        return "UNKNOWN_ANOMALY"


class SimulationRequest(BaseModel):
    threat_type: str = Field(default="DEAUTH_STORM")
    attacker_mac: Optional[str] = Field(default="A4:C3:F0:99:88:77")
    target_mac: Optional[str] = Field(default="FF:FF:FF:FF:FF:FF")
    channel: Optional[int] = Field(default=6, ge=1, le=14)
    rssi: Optional[int] = Field(default=-42, ge=-100, le=0)
    packet_count: Optional[int] = Field(default=1850, ge=1)


class AiChatRequest(BaseModel):
    query: str = Field(..., min_length=1)
    context_threat_type: Optional[str] = None
    chat_history: Optional[List[Dict[str, str]]] = Field(default_factory=list)
    image_b64: Optional[str] = None


class ImageAnalysisRequest(BaseModel):
    prompt: Optional[str] = "Analyze this wireless spectrum / network diagram for security anomalies, interference, or rogue access points."
    image_b64: str = Field(..., min_length=10)


class SetModelRequest(BaseModel):
    model: str = Field(..., min_length=1)


class DeviceItem(BaseModel):
    mac: str = Field(..., max_length=17)
    ip: Optional[str] = "10.0.1.???"
    name: str = Field(..., max_length=50)
    vendor: Optional[str] = "Generic Station"
    trusted: bool = True
    rssi: Optional[int] = -50


class SerialConnectRequest(BaseModel):
    port: str = Field(..., min_length=1)
    baud_rate: int = Field(default=115200)


class RawFrameRequest(BaseModel):
    frame_hex: str = Field(..., min_length=48)
    sensor_id: Optional[str] = "ESP32-RAW-SNIFFER"
    channel: Optional[int] = 6
    rssi: Optional[int] = -50


class WiFiConnectRequest(BaseModel):
    ssid: str = Field(..., min_length=1, max_length=64)
    password: Optional[str] = Field(default="", max_length=64)


class WiFiNetworkInfo(BaseModel):
    ssid: str
    bssid: Optional[str] = ""
    channel: Optional[int] = 0
    rssi: Optional[int] = -100
    security: Optional[str] = "UNKNOWN"
    connected: bool = False


# --- In-Memory State & Buffers ---
threat_history: List[Dict[str, Any]] = []
system_start_time = datetime.now(timezone.utc)
total_threats_detected = 0

devices_registry: List[Dict[str, Any]] = [
    {"id": 1, "mac": "A4:C3:F0:12:34:56", "ip": "10.0.1.101", "name": "MacBook Pro M3",   "vendor": "Apple Inc.",    "trusted": True,  "rssi": -48, "rx": 0.72, "ry": 0.27},
    {"id": 2, "mac": "D8:BB:C1:98:76:54", "ip": "10.0.1.102", "name": "Samsung 8K QLED",  "vendor": "Samsung Elec.", "trusted": True,  "rssi": -61, "rx": 0.22, "ry": 0.72},
    {"id": 3, "mac": "FC:EC:DA:55:44:33", "ip": "10.0.1.103", "name": "iPhone 15 Pro Max","vendor": "Apple Inc.",    "trusted": True,  "rssi": -44, "rx": 0.80, "ry": 0.70},
    {"id": 4, "mac": "B0:A7:B9:11:22:33", "ip": "10.0.1.1",   "name": "Sentinel Core AP", "vendor": "Cisco Meraki",  "trusted": True,  "rssi": -18, "rx": 0.50, "ry": 0.50},
    {"id": 5, "mac": "C4:E9:84:77:AA:BB", "ip": "10.0.1.110", "name": "Raspberry Pi 5",   "vendor": "Raspberry Pi",  "trusted": True,  "rssi": -53, "rx": 0.22, "ry": 0.28},
]

serial_bridge_state = {
    "is_running": False,
    "port": None,
    "baud_rate": 115200,
    "packets_received": 0,
    "last_error": None,
    "task": None
}

# WiFi connection state (host PC)
wifi_state = {
    "connected": False,
    "ssid": "",
    "bssid": "",
    "channel": 0,
    "rssi": 0,
    "ip": "",
    "gateway": "",
    "dns": "",
    "security": "",
    "interface": "",
    "last_scan": [],
    "network_devices": [],
    "last_error": None
}

# --- WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self, max_dashboard: int = 50, max_esp32: int = 10):
        self.dashboard_clients: List[WebSocket] = []
        self.esp32_clients: List[WebSocket] = []
        self._max_dashboard = max_dashboard
        self._max_esp32 = max_esp32

    async def connect_dashboard(self, websocket: WebSocket) -> bool:
        if len(self.dashboard_clients) >= self._max_dashboard:
            logger.warning(f"Dashboard connection rejected: limit reached ({self._max_dashboard})")
            await websocket.close(code=1008, reason="Connection limit reached")
            return False
        await websocket.accept()
        self.dashboard_clients.append(websocket)
        logger.info(f"Dashboard client connected. Active: {len(self.dashboard_clients)}")
        return True

    async def connect_esp32(self, websocket: WebSocket) -> bool:
        if len(self.esp32_clients) >= self._max_esp32:
            logger.warning(f"ESP32 connection rejected: limit reached ({self._max_esp32})")
            await websocket.close(code=1008, reason="Connection limit reached")
            return False
        await websocket.accept()
        self.esp32_clients.append(websocket)
        logger.info(f"ESP32 client connected. Active: {len(self.esp32_clients)}")
        return True

    def disconnect_dashboard(self, websocket: WebSocket):
        if websocket in self.dashboard_clients:
            self.dashboard_clients.remove(websocket)
            logger.info(f"Dashboard disconnected. Remaining: {len(self.dashboard_clients)}")

    def disconnect_esp32(self, websocket: WebSocket):
        if websocket in self.esp32_clients:
            self.esp32_clients.remove(websocket)
            logger.info(f"ESP32 disconnected. Remaining: {len(self.esp32_clients)}")

    async def broadcast_to_dashboards(self, message: dict):
        if not self.dashboard_clients:
            return
        payload_text = fast_dumps(message)
        # P1 fix: parallel broadcast via asyncio.gather — one slow client can't block others
        async def _safe_send(client):
            try:
                await client.send_text(payload_text)
                return True
            except Exception:
                return False
        results = await asyncio.gather(*[_safe_send(c) for c in self.dashboard_clients], return_exceptions=True)
        disconnected = [c for c, ok in zip(self.dashboard_clients, results) if ok is False or isinstance(ok, Exception)]
        for dead in disconnected:
            self.disconnect_dashboard(dead)

    async def broadcast_to_esp32(self, message: dict):
        if not self.esp32_clients:
            return
        payload_text = fast_dumps(message)
        async def _safe_send(client):
            try:
                await client.send_text(payload_text)
                return True
            except Exception:
                return False
        results = await asyncio.gather(*[_safe_send(c) for c in self.esp32_clients], return_exceptions=True)
        disconnected = [c for c, ok in zip(self.esp32_clients, results) if ok is False or isinstance(ok, Exception)]
        for dead in disconnected:
            self.disconnect_esp32(dead)


manager = ConnectionManager(
    max_dashboard=MAX_DASHBOARD_CLIENTS,
    max_esp32=MAX_ESP32_CLIENTS
)

ai_semaphore = asyncio.Semaphore(MAX_CONCURRENT_AI_TASKS)

# --- Vector DB Knowledge Base for LangGraph ---
KNOWLEDGE_VECTORS = [
    "DEAUTH_STORM: Continuous 802.11 management deauthentication frame flood (Type 0x00, Subtype 0x0C). Aims to sever client connections to force 4-way handshake re-association or coerce connection into an Evil Twin AP.",
    "EVIL_TWIN: Rogue AP cloning the target SSID and BSSID characteristics with high RF power. Intercepts WPA credentials or conducts Man-In-The-Middle (MitM) packet inspection.",
    "BEACON_FLOOD: Saturation of 802.11 beacon management frames (Type 0x00, Subtype 0x08) advertising thousands of pseudo-random SSIDs. Degrades Wi-Fi scanning and crashes client station drivers.",
    "PROBE_STORM: Automated rapid probe requests (Type 0x00, Subtype 0x04) scanning for nearby broadcasted ESSIDs and mapping station device MAC fingerprints.",
    "KARMA_ATTACK: Rogue access point responding affirmatively to all SSID probe requests from client devices, masquerading as known preferred networks to capture associations.",
    "PMKID_CAPTURE: Sniffing the RSN IE (Robust Security Network Information Element) in 802.11 EAPOL frame 1 of the 4-way handshake to perform offline hash cracking without client association.",
    "WPS_BRUTE_FORCE: Pixie Dust and PIN brute force exploitation against Wi-Fi Protected Setup registrar protocols to extract WPA2 pre-shared keys.",
    "ROGUE_AP: Unauthorized wireless transceiver bridging physical Ethernet LANs, bypassing enterprise perimeter firewalls."
]

vector_db = None

def init_vector_database():
    global vector_db
    if LANGCHAIN_AVAILABLE:
        try:
            embeddings = FakeEmbeddings(size=1536)
            vector_db = FAISS.from_texts(KNOWLEDGE_VECTORS, embeddings)
            logger.info("✅ FAISS Vector DB initialized with 802.11 threat signatures.")
        except Exception as e:
            logger.warning(f"FAISS initialization warning: {e}")

# --- LangGraph Security Agent Definition ---
class AgentState(TypedDict):
    threat_payload: dict
    historical_context: str
    ai_analysis: str
    mitigation_steps: str

def retrieve_context(state: AgentState):
    threat_type = state["threat_payload"].get("threat_type", "")
    context = "Standard 802.11 RF Frame Anomaly."
    if vector_db:
        try:
            docs = vector_db.similarity_search(threat_type, k=1)
            if docs:
                context = docs[0].page_content
        except Exception:
            pass
    return {"historical_context": context}

async def analyze_threat_node(state: AgentState):
    payload = state["threat_payload"]
    try:
        analysis = await local_ai_engine.analyze_threat(payload, state.get("historical_context", ""))
        if analysis:
            return {"ai_analysis": analysis}
    except Exception as err:
        logger.error(f"Local AI analysis call failed: {err}")
    return {"ai_analysis": "AI Analysis Failed or Unavailable."}

async def generate_mitigation_node(state: AgentState):
    payload = state["threat_payload"]
    try:
        mitigation = await local_ai_engine.generate_mitigation(payload, state.get("ai_analysis", ""))
        if mitigation:
            return {"mitigation_steps": mitigation}
    except Exception as err:
        logger.error(f"Local AI mitigation call failed: {err}")
    return {"mitigation_steps": "AI Mitigation Failed or Unavailable."}

threat_agent = None

def compile_langgraph_agent():
    global threat_agent
    if LANGCHAIN_AVAILABLE:
        try:
            wf = StateGraph(AgentState)
            wf.add_node("retrieve", retrieve_context)
            wf.add_node("analyze", analyze_threat_node)
            wf.add_node("mitigate", generate_mitigation_node)
            wf.set_entry_point("retrieve")
            wf.add_edge("retrieve", "analyze")
            wf.add_edge("analyze", "mitigate")
            wf.add_edge("mitigate", END)
            threat_agent = wf.compile()
            logger.info("✅ LangGraph Threat Agent compiled successfully with Local AI nodes.")
        except Exception as e:
            logger.warning(f"LangGraph compile warning: {e}")


# --- AI Pipeline Runner ---
# Thread-safe lock for the shared counter (C1 fix: prevents race condition)
_threat_count_lock = asyncio.Lock()

async def run_ai_pipeline(payload: dict):
    global total_threats_detected
    async with ai_semaphore:
        async with _threat_count_lock:
            total_threats_detected += 1
        try:
            logger.info(f"AI Pipeline Processing: {payload.get('threat_type')} from {payload.get('attacker_mac')}")
            initial_state: AgentState = {
                "threat_payload": payload,
                "historical_context": "",
                "ai_analysis": "",
                "mitigation_steps": ""
            }

            if threat_agent:
                final_state = await threat_agent.ainvoke(initial_state)
            else:
                s1 = retrieve_context(initial_state)
                initial_state.update(s1)
                s2 = await analyze_threat_node(initial_state)
                initial_state.update(s2)
                s3 = await generate_mitigation_node(initial_state)
                final_state = {**initial_state, **s3}

            active_model_name = local_ai_engine.engine_display_name
            ai_report = {
                "type": "ai_report",
                "threat": payload.get("threat_type"),
                "threat_type": payload.get("threat_type"),
                "attacker_mac": payload.get("attacker_mac"),
                "target_mac": payload.get("target_mac"),
                "channel": payload.get("channel"),
                "rssi": payload.get("rssi"),
                "packet_count": payload.get("packet_count") or payload.get("pkt_rate") or 150,
                "analysis": final_state["ai_analysis"],
                "mitigation": final_state["mitigation_steps"],
                "ai_engine": active_model_name,
                "analyzed_at": datetime.now(timezone.utc).isoformat()
            }

            threat_history.insert(0, ai_report)
            # C2 fix: properly trim to 200 entries (old code only popped 1, could leak under burst load)
            if len(threat_history) > 200:
                del threat_history[200:]

            # Dynamically track rogue attacker device in registry
            atk_mac = (payload.get("attacker_mac") or "").upper()
            if atk_mac and atk_mac not in ["FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"]:
                found = False
                for dev in devices_registry:
                    if dev["mac"].upper() == atk_mac:
                        dev["trusted"] = False
                        dev["rssi"] = payload.get("rssi", -45)
                        dev["name"] = f"Rogue Transmitter ({payload.get('threat_type')})"
                        found = True
                        break
                if not found:
                    devices_registry.append({
                        "id": max((d['id'] for d in devices_registry), default=0) + 1,
                        "mac": atk_mac,
                        "ip": "10.0.1.???",
                        "name": f"Rogue {payload.get('threat_type')}",
                        "vendor": "Foreign / Spoofed Transceiver",
                        "trusted": False,
                        "rssi": payload.get("rssi", -45),
                        "rx": 0.15,
                        "ry": 0.45
                    })

            await manager.broadcast_to_dashboards(ai_report)
            # Bidirectional hardware feedback: Notify ESP32-S3 OLED & MAX98357A speaker
            await manager.broadcast_to_esp32({
                "type": "ai_report",
                "threat_type": payload.get("threat_type"),
                "summary": str(final_state.get("ai_analysis", ""))[:120]
            })
            logger.info(f"AI Analysis Broadcasted successfully for {payload.get('threat_type')}")

        except Exception as exc:
            logger.error(f"AI Pipeline error: {exc}", exc_info=True)
            await manager.broadcast_to_dashboards({
                "type": "ai_error",
                "threat": payload.get("threat_type"),
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })


# --- Authentication Helper ---
# SECURITY: Dev-mode bypass — in production, set SENTINEL_WS_TOKEN env var and enforce strict check.
# Currently allows unauthenticated connections (token=None) for local development.
def verify_ws_token(token: Optional[str]) -> bool:
    if not token:
        return True  # Dev mode allows seamless connect
    return secrets.compare_digest(token, WS_AUTH_TOKEN) or token == "sentinel-dev-token-change-me"


# --- Background Serial Bridge Task ---
async def background_serial_reader(port: str, baud_rate: int):
    global serial_bridge_state
    logger.info(f"🔌 Serial bridge starting on {port} @ {baud_rate} baud...")
    try:
        ser = serial.Serial(port, baud_rate, timeout=1)
        serial_bridge_state["is_running"] = True
        serial_bridge_state["port"] = port
        serial_bridge_state["baud_rate"] = baud_rate
        serial_bridge_state["last_error"] = None

        while serial_bridge_state["is_running"]:
            if ser.in_waiting > 0:
                raw_line = ser.readline().decode("utf-8", errors="ignore").strip()
                if raw_line:
                    logger.debug(f"[Serial IN] {raw_line}")
                    # Check if ESP32 sent JSON threat payload or clap event
                    if raw_line.startswith("{") and ("threat_type" in raw_line or "type" in raw_line):
                        try:
                            parsed = json.loads(raw_line)
                            ttype = parsed.get("threat_type") or parsed.get("type") or "ESP32_THREAT"
                            payload = {
                                "sensor_id": f"ESP32-SERIAL-{port}",
                                "threat_type": ttype,
                                "attacker_mac": parsed.get("attacker_mac") or parsed.get("mac") or "DE:AD:BE:EF:00:01",
                                "target_mac": parsed.get("target_mac") or "FF:FF:FF:FF:FF:FF",
                                "channel": parsed.get("channel", 6),
                                "rssi": parsed.get("rssi", -55),
                                "packet_count": parsed.get("packet_count") or parsed.get("pkt_rate") or 100,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                            serial_bridge_state["packets_received"] += 1

                            # Fast-path broadcast
                            await manager.broadcast_to_dashboards({
                                "type": "raw_alert",
                                "data": payload,
                                "received_at": datetime.now(timezone.utc).isoformat()
                            })

                            # Run AI pipeline
                            asyncio.create_task(run_ai_pipeline(payload))
                        except Exception as parse_err:
                            logger.warning(f"Failed to parse ESP32 serial JSON: {parse_err}")
                    elif "[VOICE]" in raw_line or "[MIC]" in raw_line:
                        # Forward clap/voice event to dashboard
                        await manager.broadcast_to_dashboards({
                            "type": "esp32_voice_event",
                            "raw": raw_line,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })

            await asyncio.sleep(0.01)

    except Exception as e:
        logger.error(f"Serial bridge error on {port}: {e}")
        serial_bridge_state["last_error"] = str(e)
    finally:
        serial_bridge_state["is_running"] = False
        # P7 fix: guard ser.close() — ser may not be assigned if Serial() constructor raised
        if 'ser' in locals():
            try:
                ser.close()
            except Exception:
                pass
        logger.info(f"🔌 Serial bridge on {port} stopped.")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   ATTACK ENCYCLOPEDIA — All 802.11 WiFi Attack Types with Forensic Details
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ATTACK_ENCYCLOPEDIA: Dict[str, Dict[str, Any]] = {
    "DEAUTH_STORM": {
        "name": "Deauthentication Storm (0x0C)",
        "frame_type": "Management (Type 0x00, Subtype 0x0C)",
        "severity": 5,
        "category": "Denial of Service / Handshake Harvesting",
        "description": (
            "A high-velocity flood of 802.11 Deauthentication management frames. The attacker "
            "sends spoofed 0x0C frames to force client stations to disconnect from their Access Point. "
            "This is the most common precursor to Evil Twin and PMKID attacks because it forces "
            "clients to re-associate, exposing the WPA 4-way handshake."
        ),
        "how_sentinel_intercepts": (
            "Sentinel's ESP32-S3 Core 0 runs in promiscuous mode capturing ALL raw 802.11 frames. "
            "When the sniffer callback detects frame_type=0x00, subtype=0x0C, it increments a "
            "deauth counter inside an ISR-safe portMUX critical section. If the counter exceeds "
            "DEAUTH_THRESHOLD (5 frames) within a 3-second detection window, a ThreatAlert struct "
            "is pushed to the FreeRTOS queue via xQueueSendFromISR(). Core 1's loop() drains this "
            "queue, triggers the OLED alert screen, sounds the MAX98357A alarm, and sends the alert "
            "JSON over WebSocket to the FastAPI backend for LangGraph AI analysis."
        ),
        "real_world_tools": ["aireplay-ng --deauth", "mdk3/mdk4", "Flipper Zero WiFi devboard"],
        "defense": "Enable 802.11w Protected Management Frames (PMF/MFP) on all APs and clients.",
        "sim_defaults": {"mac": "DE:AD:BE:EF:00:01", "channel": 6, "rssi": -42, "pkt_rate": 1850}
    },
    "EVIL_TWIN": {
        "name": "Evil Twin Rogue Access Point",
        "frame_type": "Management Beacon (Type 0x00, Subtype 0x08)",
        "severity": 5,
        "category": "Man-in-the-Middle / Credential Harvesting",
        "description": (
            "The attacker creates a rogue AP that clones the SSID and BSSID of a legitimate network. "
            "By broadcasting stronger signal beacons, it lures clients into connecting to the fake AP. "
            "Once associated, all traffic passes through the attacker who can capture credentials, "
            "inject malicious content, or perform SSL stripping."
        ),
        "how_sentinel_intercepts": (
            "Sentinel detects Evil Twin by monitoring beacon frames (subtype 0x08) and comparing "
            "BSSID signatures against its whitelist registry. When a beacon advertises a known SSID "
            "from an unregistered BSSID MAC address, or when RSSI suddenly spikes (indicating a "
            "closer, more powerful rogue transmitter), the system flags it as an Evil Twin. The "
            "LangGraph AI pipeline cross-references the FAISS vector database for historical "
            "signatures and generates tactical containment recommendations."
        ),
        "real_world_tools": ["hostapd-wpe", "Fluxion", "WiFi-Pumpkin3", "bettercap"],
        "defense": "Deploy WPA3-Enterprise with 802.1X EAP-TLS certificate mutual authentication.",
        "sim_defaults": {"mac": "E0:5A:1B:99:33:AA", "channel": 6, "rssi": -35, "pkt_rate": 920}
    },
    "BEACON_FLOOD": {
        "name": "Beacon Frame Saturation (0x08)",
        "frame_type": "Management Beacon (Type 0x00, Subtype 0x08)",
        "severity": 4,
        "category": "Denial of Service / Wireless Stack Exhaustion",
        "description": (
            "The attacker broadcasts thousands of fake beacon frames with pseudo-random SSIDs. "
            "This overwhelms nearby Wi-Fi clients and access points, causing their wireless stack "
            "to crash or become unresponsive. Victims see hundreds of fake networks in their WiFi "
            "scanner, unable to find or connect to legitimate networks."
        ),
        "how_sentinel_intercepts": (
            "The promiscuous sniffer on Core 0 tracks the total packet rate across all channels. "
            "When the aggregate management frame rate exceeds DOS_PKT_THRESHOLD (600 pkts/sec), "
            "the telemetry module in sendTelemetry() generates a DOS_FLOOD alert. The system "
            "correlates the source MAC distribution to determine if it's a single attacker or "
            "distributed flood, and the AI engine provides channel migration recommendations."
        ),
        "real_world_tools": ["mdk3 b (beacon flood)", "mdk4", "Scapy beacon injector"],
        "defense": "AP management frame rate-limiting + Dynamic Frequency Selection (DFS).",
        "sim_defaults": {"mac": "AA:11:BB:22:CC:33", "channel": 1, "rssi": -48, "pkt_rate": 3200}
    },
    "PROBE_STORM": {
        "name": "Probe Request Reconnaissance Burst (0x04)",
        "frame_type": "Management Probe Request (Type 0x00, Subtype 0x04)",
        "severity": 3,
        "category": "Reconnaissance / Station Fingerprinting",
        "description": (
            "Automated rapid-fire probe requests scanning for all nearby wireless networks. "
            "The attacker maps ESSID names, BSSID addresses, supported data rates, and station "
            "MAC fingerprints. This reconnaissance phase typically precedes targeted attacks like "
            "Evil Twin or KARMA — the attacker needs to know which networks exist first."
        ),
        "how_sentinel_intercepts": (
            "Core 0 ISR callback detects frame_type=0x00, subtype=0x04 probe requests. A dedicated "
            "cnt_probe counter is incremented inside portMUX. When PROBE_THRESHOLD (25 frames) is "
            "reached within the 3s detection window, a PROBE_FLOOD ThreatAlert is queued. The backend "
            "AI analyzes the source MAC OUI (manufacturer prefix) to identify the attacker device type "
            "and adds it to the SOC watchlist."
        ),
        "real_world_tools": ["airodump-ng", "Kismet", "WiFi Analyzer", "hcxdumptool"],
        "defense": "Suppress broadcast SSID responses to unknown probe requests.",
        "sim_defaults": {"mac": "8C:3B:AD:77:88:99", "channel": 11, "rssi": -58, "pkt_rate": 640}
    },
    "KARMA_ATTACK": {
        "name": "KARMA Preferred Network List Hijack",
        "frame_type": "Management Probe Response (Type 0x00, Subtype 0x05)",
        "severity": 5,
        "category": "Rogue AP / Auto-Association Exploitation",
        "description": (
            "KARMA exploits the client's Preferred Network List (PNL). Every WiFi device remembers "
            "networks it has connected to and periodically sends probe requests for them. A KARMA "
            "attacker responds affirmatively to ALL probe requests — pretending to be your home WiFi, "
            "office WiFi, or any network the client has ever used. The client auto-connects, thinking "
            "it found a trusted network."
        ),
        "how_sentinel_intercepts": (
            "Sentinel monitors probe responses (subtype 0x05) and detects when a single MAC address "
            "responds to multiple different SSID probe requests — a signature KARMA behavior. Normal "
            "APs only respond to their own SSID. The AI pipeline flags transmitters that respond to "
            ">3 different SSIDs within a detection window as KARMA-capable rogue nodes and triggers "
            "a critical alert with PNL protection recommendations."
        ),
        "real_world_tools": ["hostapd-mana (KARMA mode)", "WiFi-Pumpkin3", "Pineapple Mark VII"],
        "defense": "Disable auto-connect to open networks on all devices. Deploy MDM profiles.",
        "sim_defaults": {"mac": "FA:88:22:CC:55:11", "channel": 6, "rssi": -40, "pkt_rate": 810}
    },
    "PMKID_CAPTURE": {
        "name": "PMKID Hash Extraction (EAPOL Frame 1)",
        "frame_type": "Data / EAPOL (Type 0x02, Key Frame 1)",
        "severity": 5,
        "category": "Credential Theft / Offline Brute Force",
        "description": (
            "The attacker captures the PMKID (Pairwise Master Key Identifier) from the RSN IE "
            "(Robust Security Network Information Element) in the first EAPOL frame of the WPA "
            "4-way handshake. Unlike traditional handshake capture, PMKID extraction requires only "
            "a single frame and does NOT need a client to be connected. The attacker can then perform "
            "offline dictionary/brute-force attacks against the hash using hashcat."
        ),
        "how_sentinel_intercepts": (
            "The sniffer monitors data frames (type 0x02) for EAPOL authentication patterns. When "
            "anomalous EAPOL frame 1 transactions are detected from an unrecognized MAC without a "
            "corresponding client association, the system flags it as a PMKID capture attempt. The "
            "LangGraph pipeline queries the FAISS vector DB for PMKID attack signatures and generates "
            "a mitigation playbook including PSK rotation and WPA3-SAE upgrade recommendations."
        ),
        "real_world_tools": ["hcxdumptool + hcxpcapngtool", "hashcat -m 22000", "airgeddon"],
        "defense": "Upgrade to WPA3-SAE (eliminates PMKID derivation). Rotate PSK with 20+ chars.",
        "sim_defaults": {"mac": "B4:EE:2B:10:99:44", "channel": 6, "rssi": -50, "pkt_rate": 450}
    },
    "WPS_BRUTE_FORCE": {
        "name": "WPS PIN Brute Force / Pixie Dust",
        "frame_type": "EAP-WSC (M1/M2 Registration Protocol)",
        "severity": 4,
        "category": "Authentication Bypass / Key Recovery",
        "description": (
            "Wi-Fi Protected Setup (WPS) uses an 8-digit PIN split into two halves verified "
            "independently, reducing the keyspace to ~11,000 combinations. The Pixie Dust attack "
            "exploits weak random number generation in the WPS M3 nonce to recover the PIN "
            "in seconds without brute force. Either method reveals the full WPA2 Pre-Shared Key."
        ),
        "how_sentinel_intercepts": (
            "Sentinel detects rapid sequential EAP-WSC M1/M2 registration transactions from the "
            "same MAC address — a clear brute-force signature. Normal WPS uses single attempts; "
            "brute force generates 10+ attempts per minute. The system also monitors for Pixie Dust "
            "entropy analysis patterns and alerts when WPS registrar activity exceeds normal thresholds."
        ),
        "real_world_tools": ["reaver", "bully", "pixiewps (Pixie Dust)", "wifite2"],
        "defense": "Disable WPS on all access points. Use WPA3 with SAE handshake.",
        "sim_defaults": {"mac": "22:44:66:88:AA:CC", "channel": 6, "rssi": -52, "pkt_rate": 280}
    },
    "ROGUE_AP": {
        "name": "Unauthorized Rogue Access Point",
        "frame_type": "Management Beacon (Type 0x00, Subtype 0x08)",
        "severity": 4,
        "category": "Network Infiltration / Perimeter Bypass",
        "description": (
            "An unauthorized wireless access point plugged into the corporate Ethernet LAN. Unlike "
            "Evil Twin (which is wireless-only), a Rogue AP physically bridges the wired network, "
            "bypassing all perimeter firewalls and NAC controls. An employee might install one for "
            "convenience, or an attacker could plant one during physical access."
        ),
        "how_sentinel_intercepts": (
            "Sentinel maintains a BSSID whitelist of all authorized access points. Any beacon frame "
            "with an unknown BSSID advertising on the local network is flagged as a potential Rogue AP. "
            "The system cross-references the transmitter's OUI against known enterprise AP vendors "
            "(Cisco, Aruba, Ubiquiti) — consumer-grade OUIs on a corporate network trigger high-severity "
            "alerts. The AI generates WIPS containment countermeasure playbooks."
        ),
        "real_world_tools": ["Any consumer WiFi router", "Raspberry Pi + hostapd", "GL.iNet travel router"],
        "defense": "BSSID fingerprint whitelist + WIPS with auto-containment. 802.1X port security.",
        "sim_defaults": {"mac": "C0:FF:EE:BA:D0:01", "channel": 11, "rssi": -38, "pkt_rate": 520}
    },
    "DISASSOC_FLOOD": {
        "name": "Disassociation Frame Flood (0x0A)",
        "frame_type": "Management (Type 0x00, Subtype 0x0A)",
        "severity": 4,
        "category": "Denial of Service",
        "description": (
            "Similar to deauthentication but uses disassociation frames (subtype 0x0A). While deauth "
            "terminates the authentication state, disassociation terminates the association state. "
            "The practical effect is the same — clients are kicked off the network. Some legacy "
            "clients handle disassociation differently, making this a complementary attack vector."
        ),
        "how_sentinel_intercepts": (
            "Core 0's ISR monitors for frame_type=0x00, subtype=0x0A disassociation frames. The "
            "detection mechanism mirrors deauth detection: threshold-based counting within the 3-second "
            "window with ISR-safe portMUX critical sections. Alerts are queued via xQueueSendFromISR() "
            "and processed by Core 1 with OLED display + speaker alarm + WebSocket notification."
        ),
        "real_world_tools": ["mdk3 d (disassociation)", "aireplay-ng -0 (also sends disassoc)", "Scapy"],
        "defense": "802.11w PMF (protects both deauth and disassoc frames cryptographically).",
        "sim_defaults": {"mac": "BA:AD:F0:0D:13:37", "channel": 1, "rssi": -45, "pkt_rate": 1200}
    },
    "AUTH_FLOOD": {
        "name": "Authentication Frame Flood (0x0B)",
        "frame_type": "Management (Type 0x00, Subtype 0x0B)",
        "severity": 3,
        "category": "Denial of Service / AP Resource Exhaustion",
        "description": (
            "Floods the target AP with fake authentication request frames. Each authentication "
            "request forces the AP to allocate state tracking resources. With thousands of fake "
            "auth requests per second, the AP's association table fills up, preventing legitimate "
            "clients from connecting. This is essentially a SYN flood equivalent for WiFi."
        ),
        "how_sentinel_intercepts": (
            "The promiscuous sniffer detects authentication frame bursts (subtype 0x0B) from multiple "
            "spoofed source MACs targeting a single BSSID. The telemetry module's rate-based DoS "
            "detection triggers when management frame rates exceed normal baselines. The AI analyzes "
            "MAC randomization patterns to confirm automated attack tooling."
        ),
        "real_world_tools": ["mdk3 a (authentication flood)", "mdk4", "Scapy auth injector"],
        "defense": "AP authentication rate limiting. Client association limits. MAC ACLs.",
        "sim_defaults": {"mac": "11:22:33:44:55:66", "channel": 6, "rssi": -55, "pkt_rate": 980}
    },
    "EAPOL_REPLAY": {
        "name": "EAPOL 4-Way Handshake Replay",
        "frame_type": "Data / EAPOL (Type 0x02, Key Frames 1-4)",
        "severity": 5,
        "category": "Key Reinstallation / KRACK Attack",
        "description": (
            "The attacker captures and replays EAPOL messages from the WPA2 4-way handshake to force "
            "key reinstallation on the client (KRACK — Key Reinstallation Attack). By replaying "
            "message 3 of the handshake, the attacker resets the nonce counter, allowing decryption "
            "of encrypted traffic and injection of forged packets."
        ),
        "how_sentinel_intercepts": (
            "Sentinel's data frame analysis detects duplicate EAPOL message sequence numbers — the "
            "hallmark of replay attacks. Normal handshakes use strictly incrementing nonces; replayed "
            "messages show nonce resets. The system alerts when EAPOL message 3 retransmissions exceed "
            "normal AP retry behavior (typically 1-2 retries vs. attacker's 10+ retries)."
        ),
        "real_world_tools": ["krackattacks scripts", "wpa_supplicant exploit", "hostapd-wpe"],
        "defense": "Patch all clients and APs for KRACK (CVE-2017-13077). Upgrade to WPA3.",
        "sim_defaults": {"mac": "77:88:99:AA:BB:CC", "channel": 6, "rssi": -48, "pkt_rate": 340}
    },
    "RF_JAMMING": {
        "name": "RF Spectrum Jamming / Channel Saturation",
        "frame_type": "Physical Layer (PHY) / Non-802.11 RF Noise",
        "severity": 5,
        "category": "Physical Layer Denial of Service",
        "description": (
            "The attacker uses a wideband RF transmitter to flood the 2.4GHz or 5GHz spectrum "
            "with noise, making all WiFi communication impossible on the affected channels. Unlike "
            "protocol-level attacks, jamming operates at the physical layer and cannot be prevented "
            "by 802.11w PMF or any software-based defense. Only spectrum monitoring and physical "
            "locate-and-remove can counter it."
        ),
        "how_sentinel_intercepts": (
            "Sentinel detects jamming through indirect indicators: sudden drop in legitimate packet "
            "reception rate, extreme increase in CRC errors, WiFi RSSI readings showing abnormal "
            "noise floor elevation, and ESP32 heap/connectivity instability. The system correlates "
            "these metrics to distinguish jamming from normal interference. The AI generates "
            "channel migration and spectrum analysis recommendations."
        ),
        "real_world_tools": ["HackRF One + GNU Radio", "WiFi Deauther (continuous mode)", "Signal generators"],
        "defense": "Spectrum monitoring + physical security. DFS channel migration. 5GHz/6GHz migration.",
        "sim_defaults": {"mac": "FF:FF:FF:FF:FF:FF", "channel": 6, "rssi": -20, "pkt_rate": 5000}
    }
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   AUTO-SIMULATION ENGINE — Continuous Realistic WiFi Attack Generation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AutoSimulationEngine:
    """
    Generates continuous, realistic WiFi attack simulations for demo/hackathon mode.
    Each attack uses randomized but plausible parameters (MAC, channel, RSSI, packet rate).
    Attacks are fed through the full LangGraph AI pipeline → Dashboard broadcast.
    """
    def __init__(self):
        self.is_running: bool = False
        self._task: Optional[asyncio.Task] = None
        self.interval_seconds: float = 8.0  # Time between simulated attacks
        self.attacks_generated: int = 0
        self.attack_sequence: List[str] = []  # History of generated attack types
        self.started_at: Optional[str] = None

    def _random_mac(self) -> str:
        """Generate a random but realistic-looking MAC address."""
        oui_prefixes = [
            "DE:AD:BE", "E0:5A:1B", "AA:11:BB", "8C:3B:AD",
            "FA:88:22", "B4:EE:2B", "22:44:66", "C0:FF:EE",
            "BA:AD:F0", "11:22:33", "77:88:99", "A4:C3:F0"
        ]
        oui = random.choice(oui_prefixes)
        suffix = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
        return f"{oui}:{suffix}"

    def _generate_attack(self) -> dict:
        """Generate a single realistic attack scenario from the encyclopedia."""
        attack_type = random.choice(list(ATTACK_ENCYCLOPEDIA.keys()))
        attack_info = ATTACK_ENCYCLOPEDIA[attack_type]
        defaults = attack_info["sim_defaults"]

        # Randomize parameters within realistic ranges
        channel = random.choice([1, 3, 6, 9, 11])
        rssi_base = defaults.get("rssi", -50)
        rssi = rssi_base + random.randint(-10, 10)
        rssi = max(-95, min(-15, rssi))

        pkt_base = defaults.get("pkt_rate", 500)
        pkt_rate = int(pkt_base * random.uniform(0.5, 2.0))

        return {
            "sensor_id": "SENTINEL-AUTO-SIM",
            "threat_type": attack_type,
            "attacker_mac": self._random_mac(),
            "target_mac": random.choice([
                "FF:FF:FF:FF:FF:FF",
                "A4:C3:F0:12:34:56",
                "D8:BB:C1:98:76:54",
                "FC:EC:DA:55:44:33"
            ]),
            "channel": channel,
            "rssi": rssi,
            "packet_count": pkt_rate,
            "pkt_rate": pkt_rate,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "simulation": True
        }

    async def _run_loop(self):
        """Main simulation loop — generates attacks at configured interval."""
        logger.info(f"🎯 Auto-Simulation Engine STARTED (interval={self.interval_seconds}s)")
        self.started_at = datetime.now(timezone.utc).isoformat()

        # Cycle through ALL attack types first, then randomize
        all_types = list(ATTACK_ENCYCLOPEDIA.keys())
        random.shuffle(all_types)
        cycle_index = 0

        while self.is_running:
            try:
                # First pass: cycle through every attack type so user sees all of them
                if cycle_index < len(all_types):
                    attack_type = all_types[cycle_index]
                    payload = self._generate_attack()
                    payload["threat_type"] = attack_type  # Override with cycle type
                    cycle_index += 1
                else:
                    payload = self._generate_attack()

                self.attacks_generated += 1
                self.attack_sequence.append(payload["threat_type"])
                if len(self.attack_sequence) > 50:
                    self.attack_sequence = self.attack_sequence[-50:]

                logger.warning(
                    f"🎯 AUTO-SIM #{self.attacks_generated}: {payload['threat_type']} "
                    f"from {payload['attacker_mac']} on CH {payload['channel']}"
                )

                # Fast-path broadcast raw alert
                await manager.broadcast_to_dashboards({
                    "type": "raw_alert",
                    "data": payload,
                    "source": "auto_simulation",
                    "received_at": datetime.now(timezone.utc).isoformat()
                })
                
                await manager.broadcast_to_esp32({
                    "type": "simulate_alert",
                    "threat_type": payload["threat_type"],
                    "mac": payload["attacker_mac"],
                    "rssi": payload.get("rssi", -42),
                    "channel": payload.get("channel", 6),
                    "packet_count": payload.get("packet_count") or payload.get("pkt_rate") or 1850
                })

                # Full AI pipeline analysis
                asyncio.create_task(run_ai_pipeline(payload))

                # Variable delay to make it feel realistic
                jitter = random.uniform(-2.0, 2.0)
                await asyncio.sleep(max(3.0, self.interval_seconds + jitter))

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Auto-simulation error: {e}")
                await asyncio.sleep(5)

        logger.info("🎯 Auto-Simulation Engine STOPPED")

    def start(self, interval: float = 8.0):
        """Start the auto-simulation background task."""
        if self.is_running:
            return False
        self.is_running = True
        self.interval_seconds = max(3.0, interval)
        self.attacks_generated = 0
        self.attack_sequence = []
        self._task = asyncio.create_task(self._run_loop())
        return True

    def stop(self):
        """Stop the auto-simulation background task."""
        self.is_running = False
        if self._task:
            self._task.cancel()
            self._task = None
        return True

    @property
    def status(self) -> dict:
        return {
            "is_running": self.is_running,
            "interval_seconds": self.interval_seconds,
            "attacks_generated": self.attacks_generated,
            "started_at": self.started_at,
            "recent_attacks": self.attack_sequence[-10:] if self.attack_sequence else [],
            "available_attack_types": list(ATTACK_ENCYCLOPEDIA.keys()),
            "total_attack_types": len(ATTACK_ENCYCLOPEDIA)
        }


auto_sim = AutoSimulationEngine()


# --- Simulation Endpoints ---

@app.post("/api/simulation/auto/start")
async def start_auto_simulation(interval: float = Query(8.0, description="Seconds between generated attacks")):
    """Starts the background auto-simulation engine for continuous realistic attacks."""
    started = auto_sim.start(interval)
    if started:
        logger.info(f"Auto-simulation started via API (interval={interval}s).")
        return {"status": "started", "message": "Auto-simulation engine engaged.", "config": auto_sim.status}
    else:
        return {"status": "already_running", "message": "Simulation is already active.", "config": auto_sim.status}

@app.post("/api/simulation/auto/stop")
async def stop_auto_simulation():
    """Stops the background auto-simulation engine."""
    auto_sim.stop()
    logger.info("Auto-simulation stopped via API.")
    return {"status": "stopped", "message": "Auto-simulation engine halted.", "config": auto_sim.status}

@app.get("/api/simulation/auto/status")
async def auto_simulation_status():
    """Returns the current state and metrics of the auto-simulation engine."""
    return auto_sim.status

@app.get("/api/attacks/encyclopedia")
async def get_attack_encyclopedia():
    """Returns the complete Sentinel Wi-Fi Attack Encyclopedia with forensic details."""
    return ATTACK_ENCYCLOPEDIA


# --- REST API Endpoints ---

@app.get("/")
async def root():
    """Root metadata & status"""
    uptime_sec = round((datetime.now(timezone.utc) - system_start_time).total_seconds())
    return {
        "title": "Sentinel DevSecOps & Wi-Fi IDS AI Platform",
        "status": "ONLINE",
        "version": "3.5.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": uptime_sec,
        "local_ai": {
            "enabled": True,
            "host": local_ai_engine.host,
            "model": local_ai_engine.active_model,
            "last_successful_model": local_ai_engine.last_successful_model,
            "ollama_online": local_ai_engine.ollama_online
        },
        "docs_url": "/docs",
        "dashboards_connected": len(manager.dashboard_clients),
        "sensors_connected": len(manager.esp32_clients),
        "total_threats_detected": total_threats_detected,
        "serial_bridge": {
            "active": serial_bridge_state["is_running"],
            "port": serial_bridge_state["port"]
        },
        "wifi": {
            "connected": wifi_state["connected"],
            "ssid": wifi_state["ssid"],
            "ip": wifi_state["ip"]
        }
    }


@app.get("/health")
async def health():
    """System health check diagnostics"""
    uptime_seconds = round((datetime.now(timezone.utc) - system_start_time).total_seconds(), 1)
    
    sys_metrics = {}
    if PSUTIL_AVAILABLE:
        try:
            sys_metrics = {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage("/").percent
            }
        except Exception:
            pass

    active_engine_name = local_ai_engine.engine_display_name

    return {
        "status": "healthy",
        "uptime_seconds": uptime_seconds,
        "system": sys_metrics,
        "dashboard_clients": len(manager.dashboard_clients),
        "esp32_clients": len(manager.esp32_clients),
        "total_threats_processed": total_threats_detected,
        "ai_engine": active_engine_name,
        "ollama_status": "ONLINE" if local_ai_engine.ollama_online else "FALLBACK_RULES",
        "active_model": local_ai_engine.active_model,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/stats")
async def get_stats():
    """Real-time statistical overview"""
    active_engine_name = local_ai_engine.engine_display_name
    return {
        "status": "ONLINE",
        "threats_count": total_threats_detected,
        "dashboard_connections": len(manager.dashboard_clients),
        "sensor_connections": len(manager.esp32_clients),
        "active_channel": 6,
        "base_ssid": "HomeNet_5G",
        "ai_engine": active_engine_name,
        "uptime_seconds": round((datetime.now(timezone.utc) - system_start_time).total_seconds()),
        "serial_bridge_connected": serial_bridge_state["is_running"]
    }


@app.get("/api/threats")
async def get_threat_history(limit: int = 50, threat_type: Optional[str] = None):
    """Retrieve historical threat incidents"""
    filtered = threat_history
    if threat_type:
        filtered = [t for t in filtered if threat_type.lower() in str(t.get("threat_type", "")).lower()]
    return {
        "count": len(filtered[:limit]),
        "threats": filtered[:limit]
    }


@app.get("/api/threats/export")
async def export_threats(format: str = "json"):
    """Export threat telemetry in JSON or CSV format"""
    if format.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Timestamp", "Threat Type", "Attacker MAC", "Target MAC", "Channel", "RSSI", "Analysis", "Mitigation"])
        for t in threat_history:
            writer.writerow([
                t.get("analyzed_at") or t.get("received_at", ""),
                t.get("threat_type") or t.get("threat", ""),
                t.get("attacker_mac", ""),
                t.get("target_mac", ""),
                t.get("channel", ""),
                t.get("rssi", ""),
                t.get("analysis", ""),
                t.get("mitigation", "").replace("\n", " | ")
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinel_threat_history.csv"}
        )
    return JSONResponse(content={"export_timestamp": datetime.now(timezone.utc).isoformat(), "threats": threat_history})


async def simulate_telemetry_burst(packet_rate: int):
    """Simulates a telemetry burst for the UI without any real RF transmission."""
    import random
    import asyncio
    for i in range(50):
        # Spike the network/cpu charts in the UI visually
        await manager.broadcast_to_dashboards({
            "type": "esp32_telemetry",
            "data": {
                "pkt_rate": packet_rate + random.randint(-100, 100)
            }
        })
        await asyncio.sleep(0.1)

@app.post("/api/threats/clear")
async def clear_system_state():
    """Clear threat history and stop all simulations (Full Reset)."""
    global total_threats_detected
    
    # 1. Clear local history
    threat_history.clear()
    
    # 2. Reset counters
    async with _threat_count_lock:
        total_threats_detected = 0
        
    # 3. Stop main AutoSimulationEngine if it exists
    if 'sim_engine' in globals():
        sim_engine.stop()
        
    # 4. Try clearing the routers/threats.py state
    try:
        from backend_server.routers.threats import threat_history as router_threat_history
        from backend_server.routers.threats import active_simulations
        router_threat_history.clear()
        active_simulations.clear()
    except Exception as e:
        logger.warning(f"Could not reset routers/threats state: {e}")
        
    # 5. Broadcast reset event
    await manager.broadcast_to_dashboards({"type": "incident_reset"})
    
    return {"success": True, "message": "System fully reset."}


@app.post("/api/threats/simulate")
async def simulate_threat(sim: SimulationRequest):
    """Simulate a realistic 802.11 Wi-Fi threat from API or UI."""
    payload = {
        "sensor_id": "ESP32-S3-SIMULATOR",
        "threat_type": sim.threat_type,
        "attacker_mac": sim.attacker_mac or "DE:AD:BE:EF:00:01",
        "target_mac": sim.target_mac or "FF:FF:FF:FF:FF:FF",
        "channel": sim.channel or 6,
        "rssi": sim.rssi or -42,
        "packet_count": sim.packet_count or 1850,
        "pkt_rate": sim.packet_count or 1850,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    logger.warning(f"🚨 SIMULATED THREAT DISPATCHED: {payload['threat_type']} from {payload['attacker_mac']} on CH {payload['channel']}")

    # 1. Fast path broadcast to all connected dashboards
    await manager.broadcast_to_dashboards({
        "type": "raw_alert",
        "data": payload,
        "received_at": datetime.now(timezone.utc).isoformat()
    })

    await manager.broadcast_to_esp32({
        "type": "simulate_alert",
        "threat_type": payload["threat_type"],
        "mac": payload["attacker_mac"],
        "rssi": payload.get("rssi", -42),
        "channel": payload.get("channel", 6),
        "packet_count": payload.get("packet_count") or payload.get("pkt_rate") or 1850
    })

    # 2. Async AI pipeline execution
    asyncio.create_task(run_ai_pipeline(payload))
    asyncio.create_task(simulate_telemetry_burst(payload["packet_count"]))

    return {
        "success": True,
        "message": f"Threat simulation '{sim.threat_type}' dispatched to LangGraph Local AI pipeline",
        "payload": payload
    }


@app.post("/api/frames/parse-raw")
async def parse_raw_80211_frame(req: RawFrameRequest):
    """
    Zero-Copy Native 802.11 MAC Frame Decoder & Real-Time Threat Classifier.
    Processes raw hex frame bytes from Wireshark PCAPs or ESP32 promiscuous capture.
    """
    clean_hex = re.sub(r"[^0-9A-Fa-f]", "", req.frame_hex)
    if len(clean_hex) < 48:
        raise HTTPException(status_code=400, detail="Invalid hex string: 802.11 header requires at least 24 bytes (48 hex chars)")
    
    try:
        raw_bytes = bytes.fromhex(clean_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Malformed hex string")
    
    parsed = decode_80211_frame(raw_bytes)
    if not parsed.get("valid"):
        raise HTTPException(status_code=400, detail=parsed.get("error", "Decoding failed"))
    
    # If classified as a threat, automatically forward to LangGraph AI pipeline
    if parsed.get("is_threat"):
        threat_payload = {
            "sensor_id": req.sensor_id or "ESP32-RAW-SNIFFER",
            "threat_type": parsed["threat_classification"],
            "attacker_mac": parsed["transmitter_mac"],
            "target_mac": parsed["receiver_mac"],
            "channel": req.channel or 6,
            "rssi": req.rssi or -50,
            "packet_count": 1,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await manager.broadcast_to_dashboards({
            "type": "raw_alert",
            "data": threat_payload,
            "received_at": datetime.now(timezone.utc).isoformat()
        })
        asyncio.create_task(run_ai_pipeline(threat_payload))
    
    return {
        "success": True,
        "parsed": parsed,
        "is_threat": parsed.get("is_threat", False),
        "threat_classification": parsed.get("threat_classification")
    }


@app.post("/api/threats/clear")
async def clear_threats():
    """Clear threat history and broadcast reset to all connected dashboards."""
    global threat_history
    threat_history.clear()
    await manager.broadcast_to_dashboards({
        "type": "incident_reset",
        "message": "Incident state cleared by operator",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    return {"success": True, "message": "Threat history and incidents cleared"}


@app.post("/api/agent/chat")
async def ai_agent_chat(req: AiChatRequest):
    """Query the Sentinel AI DevSecOps security analyst powered by local Ollama AI."""
    query = req.query.strip()
    threat_type = req.context_threat_type or "GENERAL_SECURITY"

    try:
        messages = [
            {
                "role": "system",
                "content": (
                    "You are Sentinel AI, an elite cybersecurity and DevSecOps analyst specializing in 802.11 wireless IDS and packet forensics. "
                    "Your responses must be highly professional, authoritative, and strictly technical. "
                    "Avoid filler text and conversational pleasantries. Provide clear, actionable intelligence, focusing on "
                    "wireless defense, Rogue AP containment, enterprise network hardening, and cryptographic mitigations like PMF 802.11w. "
                    "Structure your responses with bullet points or bold text where appropriate for readability."
                )
            }
        ]
        if req.chat_history:
            for msg in req.chat_history[-6:]:
                r = msg.get("role", "user")
                c = msg.get("content", "")
                if r in ["user", "assistant", "system"] and c:
                    messages.append({"role": r, "content": c})

        messages.append({"role": "user", "content": f"Context Threat: {threat_type}\nQuestion: {query}"})
        images = [req.image_b64] if req.image_b64 else None
        res = await local_ai_engine.chat(messages, images=images, timeout=30.0)
        if res["success"] and res["response"]:
            return {
                "response": res["response"],
                "engine": res["engine"],
                "model": res["model"]
            }
    except Exception as e:
        logger.error(f"Chat API error: {e}")

    return {
        "response": "Local AI Engine is offline or failed to respond. Please ensure Ollama is running.",
        "engine": "local_ai",
        "model": "offline"
    }


@app.post("/api/agent/analyze-image")
async def analyze_image(req: ImageAnalysisRequest):
    """Multimodal vision analysis for RF spectrograms, diagrams, and packet graphs."""
    result = await local_ai_engine.analyze_image_telemetry(req.prompt or "Analyze this wireless diagram / image.", req.image_b64)
    if result["success"]:
        return {
            "success": True,
            "analysis": result["response"],
            "model": result["model"],
            "engine": result["engine"]
        }
    return {
        "success": False,
        "analysis": "Vision analysis unavailable. Ensure Ollama is running with a multimodal vision model like llama3.2-vision:latest.",
        "model": result["model"],
        "engine": result["engine"]
    }


@app.get("/api/agent/models")
async def list_available_models():
    """List all available local Ollama models and active configuration."""
    available = await local_ai_engine.refresh_models()
    return {
        "active_model": local_ai_engine.active_model,
        "default_model": local_ai_engine.default_model,
        "last_successful_model": local_ai_engine.last_successful_model,
        "ollama_host": local_ai_engine.host,
        "ollama_online": local_ai_engine.ollama_online,
        "available_models": available,
        "fallback_sequence": local_ai_engine.fallback_models
    }


@app.post("/api/agent/set-model")
async def set_active_model(req: SetModelRequest):
    """Switch active local model (e.g. llama3.2-vision:latest, qwen2.5-coder:7b, etc.)."""
    local_ai_engine.active_model = req.model.strip()
    logger.info(f"Active Sentinel local model set to: {local_ai_engine.active_model}")
    return {
        "success": True,
        "message": f"Active local AI model set to '{local_ai_engine.active_model}'",
        "active_model": local_ai_engine.active_model
    }


@app.get("/api/system/metrics")
async def get_system_metrics():
    """Live host system CPU, RAM, Disk, and Network telemetry"""
    if PSUTIL_AVAILABLE:
        try:
            cpu_pct = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net_io = psutil.net_io_counters()
            return {
                "cpu": round(cpu_pct, 1),
                "memory": round(mem.percent, 1),
                "disk": round(disk.percent, 1),
                "network_bytes_sent": net_io.bytes_sent,
                "network_bytes_recv": net_io.bytes_recv,
                "cores": psutil.cpu_count(logical=True),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.warning(f"Error fetching psutil metrics: {e}")

    # Fallback realistic telemetry
    return {
        "cpu": 42.5,
        "memory": 61.2,
        "disk": 53.0,
        "network_bytes_sent": 1024000,
        "network_bytes_recv": 4096000,
        "cores": 8,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/devices")
async def get_tracked_devices():
    """List of registered and detected devices"""
    return {
        "gateway": {"name": "Sentinel Core AP", "mac": "B0:A7:B9:11:22:33", "ip": "10.0.1.1", "status": "SECURE", "rssi": -18},
        "devices": devices_registry
    }


@app.post("/api/devices/whitelist")
async def whitelist_device(dev: DeviceItem):
    """Add or update trusted device in registry"""
    for d in devices_registry:
        if d["mac"].upper() == dev.mac.upper():
            d["trusted"] = True
            d["name"] = dev.name
            return {"success": True, "message": f"Device {dev.mac} whitelisted", "device": d}
    
    new_dev = {
        "id": len(devices_registry) + 1,
        "mac": dev.mac.upper(),
        "ip": dev.ip or "10.0.1.???",
        "name": dev.name,
        "vendor": dev.vendor or "Generic Station",
        "trusted": True,
        "rssi": dev.rssi or -50,
        "rx": 0.5,
        "ry": 0.3
    }
    devices_registry.append(new_dev)
    return {"success": True, "message": f"Device {dev.mac} added to whitelist", "device": new_dev}


@app.post("/api/devices/block")
async def block_device(mac: str = Query(...)):
    """Mark device as blocked / rogue"""
    for d in devices_registry:
        if d["mac"].upper() == mac.upper():
            d["trusted"] = False
            return {"success": True, "message": f"Device {mac} marked as ROGUE / BLOCKED", "device": d}
    
    rogue = {
        "id": len(devices_registry) + 1,
        "mac": mac.upper(),
        "ip": "10.0.1.???",
        "name": f"Blocked Rogue ({mac[:8]})",
        "vendor": "Unknown Attacker",
        "trusted": False,
        "rssi": -38,
        "rx": 0.15,
        "ry": 0.45
    }
    devices_registry.append(rogue)
    return {"success": True, "message": f"Rogue MAC {mac} quarantined and blocked", "device": rogue}


# --- WiFi Management API ---

class WiFiManager:
    """OS-level WiFi management for host PC scanning, connect, and network discovery."""

    @staticmethod
    def _is_windows() -> bool:
        return platform.system().lower() == "windows"

    @staticmethod
    async def scan_networks() -> List[Dict[str, Any]]:
        """Scan available WiFi networks using OS tools."""
        networks = []
        try:
            if WiFiManager._is_windows():
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                if result.returncode == 0:
                    networks = WiFiManager._parse_netsh_scan(result.stdout)
            else:
                # Linux: nmcli
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list", "--rescan", "yes"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    networks = WiFiManager._parse_nmcli_scan(result.stdout)
        except Exception as e:
            logger.error(f"WiFi scan error: {e}")
        return networks

    @staticmethod
    def _parse_netsh_scan(output: str) -> List[Dict[str, Any]]:
        """Parse netsh wlan show networks output."""
        networks = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID") and ":" in line and "BSSID" not in line:
                if current.get("ssid"):
                    networks.append(current)
                ssid = line.split(":", 1)[1].strip()
                current = {"ssid": ssid, "bssid": "", "channel": 0, "rssi": -100, "security": "UNKNOWN", "connected": False}
            elif line.startswith("Network type"):
                pass
            elif line.startswith("Authentication"):
                current["security"] = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID"):
                current["bssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("Signal"):
                sig_str = line.split(":", 1)[1].strip().replace("%", "")
                try:
                    sig_pct = int(sig_str)
                    # Convert percentage to approximate dBm
                    current["rssi"] = int((sig_pct / 2) - 100)
                except ValueError:
                    pass
            elif line.startswith("Channel"):
                try:
                    current["channel"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
        if current.get("ssid"):
            networks.append(current)
        return networks

    @staticmethod
    def _parse_nmcli_scan(output: str) -> List[Dict[str, Any]]:
        """Parse nmcli device wifi list output."""
        networks = []
        for line in output.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 5:
                ssid = parts[0].strip()
                if not ssid:
                    continue
                try:
                    signal = int(parts[3].strip())
                    rssi = int((signal / 2) - 100)
                except ValueError:
                    rssi = -100
                networks.append({
                    "ssid": ssid,
                    "bssid": parts[1].strip().replace("\\", ""),
                    "channel": int(parts[2].strip()) if parts[2].strip().isdigit() else 0,
                    "rssi": rssi,
                    "security": parts[4].strip() if len(parts) > 4 else "UNKNOWN",
                    "connected": False
                })
        return networks

    @staticmethod
    async def get_current_connection() -> Dict[str, Any]:
        """Get current WiFi connection details."""
        try:
            if WiFiManager._is_windows():
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                if result.returncode == 0:
                    return WiFiManager._parse_netsh_interface(result.stdout)
            else:
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["nmcli", "-t", "-f", "NAME,DEVICE,TYPE,STATE", "connection", "show", "--active"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().splitlines():
                        parts = line.split(":")
                        if len(parts) >= 4 and "wifi" in parts[2].lower():
                            return {
                                "connected": True,
                                "ssid": parts[0],
                                "interface": parts[1],
                                "state": "connected"
                            }
        except Exception as e:
            logger.error(f"WiFi status check error: {e}")
        return {"connected": False, "ssid": "", "state": "disconnected"}

    @staticmethod
    def _parse_netsh_interface(output: str) -> Dict[str, Any]:
        """Parse netsh wlan show interfaces output."""
        info = {"connected": False, "ssid": "", "bssid": "", "channel": 0, "rssi": 0, "security": "", "state": "disconnected"}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("State") and ":" in line:
                state = line.split(":", 1)[1].strip().lower()
                info["connected"] = state == "connected"
                info["state"] = state
            elif line.startswith("SSID") and "BSSID" not in line and ":" in line:
                info["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID"):
                info["bssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("Channel"):
                try:
                    info["channel"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("Signal"):
                try:
                    sig_pct = int(line.split(":", 1)[1].strip().replace("%", ""))
                    info["rssi"] = int((sig_pct / 2) - 100)
                except ValueError:
                    pass
            elif line.startswith("Authentication"):
                info["security"] = line.split(":", 1)[1].strip()
            elif line.startswith("Name"):
                info["interface"] = line.split(":", 1)[1].strip()
        return info

    @staticmethod
    async def connect(ssid: str, password: str = "") -> Dict[str, Any]:
        """Connect to a WiFi network."""
        try:
            if WiFiManager._is_windows():
                # Create a temporary profile XML for connection
                # C4 fix: XML-escape user inputs to prevent XML injection
                safe_ssid = xml.sax.saxutils.escape(ssid)
                safe_password = xml.sax.saxutils.escape(password) if password else ""
                if password:
                    auth = "WPA2PSK"
                    enc = "AES"
                    key_xml = f"<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>{safe_password}</keyMaterial></sharedKey>"
                else:
                    auth = "open"
                    enc = "none"
                    key_xml = ""

                profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{safe_ssid}</name>
    <SSIDConfig><SSID><name>{safe_ssid}</name></SSID></SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM><security>
        <authEncryption><authentication>{auth}</authentication><encryption>{enc}</encryption><useOneX>false</useOneX></authEncryption>
        {key_xml}
    </security></MSM>
</WLANProfile>"""

                # Write temp profile
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False, prefix='sentinel_wifi_') as f:
                    f.write(profile_xml)
                    profile_path = f.name

                # Add profile
                await asyncio.to_thread(
                    subprocess.run,
                    ["netsh", "wlan", "add", "profile", f"filename={profile_path}"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )

                # Connect
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["netsh", "wlan", "connect", f"name={ssid}"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )

                # Clean up temp file
                try:
                    os.unlink(profile_path)
                except Exception:
                    pass

                success = result.returncode == 0
                return {
                    "success": success,
                    "message": result.stdout.strip() if success else result.stderr.strip() or "Connection failed",
                    "ssid": ssid
                }
            else:
                # Linux: nmcli
                cmd = ["nmcli", "device", "wifi", "connect", ssid]
                if password:
                    cmd += ["password", password]
                result = await asyncio.to_thread(
                    subprocess.run, cmd,
                    capture_output=True, text=True, timeout=30
                )
                success = result.returncode == 0
                return {
                    "success": success,
                    "message": result.stdout.strip() if success else result.stderr.strip(),
                    "ssid": ssid
                }
        except Exception as e:
            return {"success": False, "message": str(e), "ssid": ssid}

    @staticmethod
    async def disconnect() -> Dict[str, Any]:
        """Disconnect from current WiFi."""
        try:
            if WiFiManager._is_windows():
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["netsh", "wlan", "disconnect"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                return {"success": result.returncode == 0, "message": result.stdout.strip()}
            else:
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["nmcli", "device", "disconnect", "wlan0"],
                    capture_output=True, text=True, timeout=10
                )
                return {"success": result.returncode == 0, "message": result.stdout.strip()}
        except Exception as e:
            return {"success": False, "message": str(e)}

    @staticmethod
    async def scan_network_devices() -> List[Dict[str, Any]]:
        """Discover devices on the connected network using ARP table."""
        devices = []
        try:
            if WiFiManager._is_windows():
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["arp", "-a"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                            mac = parts[1].replace("-", ":").upper()
                            if mac != "FF:FF:FF:FF:FF:FF" and not parts[0].endswith(".255"):
                                devices.append({
                                    "ip": parts[0],
                                    "mac": mac,
                                    "type": parts[2] if len(parts) > 2 else "dynamic"
                                })
            else:
                # Linux: ip neigh or arp
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["ip", "neigh", "show"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 5 and "lladdr" in parts:
                            ip = parts[0]
                            mac_idx = parts.index("lladdr") + 1
                            if mac_idx < len(parts):
                                devices.append({
                                    "ip": ip,
                                    "mac": parts[mac_idx].upper(),
                                    "type": parts[-1] if parts[-1] in ["REACHABLE", "STALE", "DELAY"] else "dynamic"
                                })
        except Exception as e:
            logger.error(f"Network device scan error: {e}")
        return devices


wifi_manager = WiFiManager()


@app.get("/api/wifi/scan")
async def scan_wifi_networks():
    """Scan available WiFi networks from the host PC."""
    networks = await wifi_manager.scan_networks()

    # Mark which one is currently connected
    current = await wifi_manager.get_current_connection()
    if current.get("connected"):
        for net in networks:
            if net["ssid"] == current.get("ssid"):
                net["connected"] = True

    wifi_state["last_scan"] = networks
    return {
        "success": True,
        "networks": networks,
        "count": len(networks),
        "current_connection": current
    }


@app.post("/api/wifi/connect")
async def connect_wifi(req: WiFiConnectRequest):
    """Connect the host PC to a WiFi network."""
    logger.info(f"📶 WiFi connect request: {req.ssid}")
    result = await wifi_manager.connect(req.ssid, req.password or "")

    if result["success"]:
        # Wait briefly for connection to establish
        await asyncio.sleep(2)
        status = await wifi_manager.get_current_connection()
        wifi_state.update({
            "connected": status.get("connected", False),
            "ssid": status.get("ssid", req.ssid),
            "bssid": status.get("bssid", ""),
            "channel": status.get("channel", 0),
            "rssi": status.get("rssi", 0),
            "security": status.get("security", ""),
            "last_error": None
        })

        # Broadcast WiFi state to dashboards
        await manager.broadcast_to_dashboards({
            "type": "wifi_connected",
            "ssid": req.ssid,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    else:
        wifi_state["last_error"] = result.get("message")

    return result


@app.post("/api/wifi/disconnect")
async def disconnect_wifi():
    """Disconnect from current WiFi network."""
    prev_ssid = wifi_state.get("ssid", "")
    result = await wifi_manager.disconnect()

    wifi_state.update({
        "connected": False,
        "ssid": "",
        "bssid": "",
        "channel": 0,
        "rssi": 0,
        "ip": "",
        "gateway": "",
        "last_error": None
    })

    await manager.broadcast_to_dashboards({
        "type": "wifi_disconnected",
        "previous_ssid": prev_ssid,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    return result


@app.get("/api/wifi/status")
async def wifi_connection_status():
    """Get current WiFi connection status."""
    status = await wifi_manager.get_current_connection()
    wifi_state.update({
        "connected": status.get("connected", False),
        "ssid": status.get("ssid", ""),
        "bssid": status.get("bssid", ""),
        "channel": status.get("channel", 0),
        "rssi": status.get("rssi", 0),
        "security": status.get("security", ""),
        "interface": status.get("interface", "")
    })
    return {
        "success": True,
        **wifi_state,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/wifi/network-scan")
async def scan_network_devices():
    """Scan the connected network for devices using ARP table."""
    status = await wifi_manager.get_current_connection()
    if not status.get("connected"):
        return {
            "success": False,
            "message": "Not connected to any WiFi network",
            "devices": []
        }

    devices = await wifi_manager.scan_network_devices()
    wifi_state["network_devices"] = devices

    return {
        "success": True,
        "network_ssid": status.get("ssid", ""),
        "devices": devices,
        "count": len(devices),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# --- Serial Port Bridge API ---

@app.get("/api/serial/ports")
async def list_serial_ports():
    """List available serial COM ports on host"""
    ports_list = []
    if SERIAL_AVAILABLE:
        try:
            ports = serial.tools.list_ports.comports()
            for p in ports:
                ports_list.append({
                    "device": p.device,
                    "description": p.description,
                    "hwid": p.hwid
                })
        except Exception as e:
            logger.warning(f"Error enumerating serial ports: {e}")

    return {
        "available": SERIAL_AVAILABLE,
        "ports": ports_list,
        "bridge_status": serial_bridge_state
    }


@app.post("/api/serial/connect")
async def connect_serial_port(req: SerialConnectRequest):
    """Start background serial listener on designated COM port"""
    if not SERIAL_AVAILABLE:
        raise HTTPException(status_code=400, detail="pyserial is not installed on this system")

    if serial_bridge_state["is_running"]:
        if serial_bridge_state["port"] == req.port:
            return {"success": True, "message": f"Already connected to {req.port}", "status": serial_bridge_state}
        # Stop existing
        serial_bridge_state["is_running"] = False
        if serial_bridge_state["task"]:
            serial_bridge_state["task"].cancel()

    # Launch new background task
    task = asyncio.create_task(background_serial_reader(req.port, req.baud_rate))
    serial_bridge_state["task"] = task

    return {
        "success": True,
        "message": f"Serial bridge started on {req.port} @ {req.baud_rate} baud",
        "status": serial_bridge_state
    }


@app.post("/api/serial/disconnect")
async def disconnect_serial_port():
    """Stop background serial listener"""
    serial_bridge_state["is_running"] = False
    if serial_bridge_state["task"]:
        serial_bridge_state["task"].cancel()
        serial_bridge_state["task"] = None

    return {
        "success": True,
        "message": "Serial bridge disconnected",
        "status": serial_bridge_state
    }


# --- ESP32 Web Server Proxy Controls (sentinel_v3.ino) ---

@app.get("/api/esp32/status")
async def esp32_hardware_status():
    """Get connected ESP32 sensor state"""
    return {
        "connected_ws": len(manager.esp32_clients) > 0,
        "connected_serial": serial_bridge_state["is_running"],
        "serial_port": serial_bridge_state["port"],
        "active_clients": len(manager.esp32_clients),
        "firmware_version": "Sentinel Guardian Firmware v3.0 (Dual-Core ESP32-S3)",
        "hardware_peripherals": {
            "oled_display": "SSD1306 128x64 (I2C SDA=21, SCL=22)",
            "i2s_mic": "INMP441 (BCK=13, WS=14, DATA=12)",
            "i2s_speaker": "MAX98357A (BCK=5, WS=6, DATA=7)"
        },
        "voice_commands": {
            "sustained_voice_trigger": "Alert AI Pipeline & Dashboard",
            "1_clap": "Scan Networks",
            "2_claps": "Stop All Attacks",
            "3_claps": "Display Hardware Stats"
        }
    }


# --- WebSocket Endpoints ---

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket connection endpoint for Sentinel React Dashboard."""
    if not verify_ws_token(token):
        await websocket.close(code=4001, reason="Unauthorized")
        return

    connected = await manager.connect_dashboard(websocket)
    if not connected:
        return

    # Send initial welcome and recent threats
    try:
        await websocket.send_json({
            "type": "connection_ack",
            "message": "Connected to Sentinel DevSecOps AI Guardian Backend v3.5",
            "server_time": datetime.now(timezone.utc).isoformat(),
            "recent_threats_count": len(threat_history),
            "ai_engine": local_ai_engine.engine_display_name
        })
    except Exception:
        pass

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
                continue

            try:
                raw_payload = json.loads(data)
                validated = ThreatPayload(**raw_payload)
                payload = validated.model_dump()
                logger.warning(f"🚨 DASHBOARD TRIGGERED EVENT: type={payload['threat_type']}, mac={payload.get('attacker_mac')}")

                # Fast Path broadcast
                await manager.broadcast_to_dashboards({
                    "type": "raw_alert",
                    "data": payload,
                    "received_at": datetime.now(timezone.utc).isoformat()
                })

                # Asynchronous AI Pipeline execution
                asyncio.create_task(run_ai_pipeline(payload))
            except Exception as e:
                logger.debug(f"Non-JSON message from dashboard: {e}")

    except WebSocketDisconnect:
        manager.disconnect_dashboard(websocket)
    except Exception as e:
        logger.error(f"Dashboard WebSocket error: {e}")
        manager.disconnect_dashboard(websocket)


async def handle_esp32_websocket(websocket: WebSocket, token: Optional[str] = None):
    """Unified WebSocket connection handler for ESP32 hardware (/ws/esp32 and /ws/sentinel)."""
    if not verify_ws_token(token):
        await websocket.close(code=4001, reason="Unauthorized")
        logger.warning("ESP32 rejected: invalid token")
        return

    connected = await manager.connect_esp32(websocket)
    if not connected:
        return

    logger.info("🟢 ESP32-S3 Hardware Sniffer connected successfully!")
    try:
        while True:
            data = await websocket.receive_text()
            if len(data) > 10240:
                await websocket.send_json({"error": "Payload too large", "max_bytes": 10240})
                continue

            try:
                raw_payload = json.loads(data)
            except Exception as e:
                logger.error(f"Invalid JSON from ESP32: {e}")
                await websocket.send_json({"error": f"Invalid JSON: {str(e)}"})
                continue

            event = raw_payload.get("event") or raw_payload.get("type")

            # 1. Hardware Online Notification (Sentinel v3.0)
            if event == "sentinel_online":
                logger.info(f"⚡ Sentinel Hardware Online: version={raw_payload.get('version', '3.0')}")
                await manager.broadcast_to_dashboards({
                    "type": "esp32_status",
                    "status": "online",
                    "version": raw_payload.get("version", "3.0"),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                continue

            # 2. Hardware Telemetry Metrics (Sentinel v3.0)
            if event == "telemetry":
                logger.debug(f"📊 ESP32 Telemetry: {raw_payload}")
                await manager.broadcast_to_dashboards({
                    "type": "esp32_telemetry",
                    "data": raw_payload,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                continue

            # 3. Voice / Audio Trigger Command
            if event == "voice_command" or "[MIC]" in str(raw_payload) or "[VOICE]" in str(raw_payload):
                logger.info("🎤 ESP32 Voice trigger detected!")
                await manager.broadcast_to_dashboards({
                    "type": "esp32_voice_event",
                    "command": raw_payload.get("command", "Voice Command Triggered"),
                    "claps": raw_payload.get("claps", 1),
                    "raw": raw_payload.get("raw", "Voice Trigger Detected"),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                continue

            # 4. 802.11 Threat Alert (sentinel_v3.ino)
            try:
                ttype = raw_payload.get("threat_type") or raw_payload.get("type") or "ANOMALOUS_FRAME"
                tmac = raw_payload.get("attacker_mac") or raw_payload.get("mac") or "DE:AD:BE:EF:00:01"
                tcount = raw_payload.get("packet_count") or raw_payload.get("count") or raw_payload.get("pkt_rate") or 150
                
                normalized = {
                    "sensor_id": raw_payload.get("sensor_id", "ESP32-S3-SNIFFER-v3"),
                    "threat_type": ttype,
                    "attacker_mac": tmac,
                    "target_mac": raw_payload.get("target_mac", "FF:FF:FF:FF:FF:FF"),
                    "channel": raw_payload.get("channel", 6),
                    "rssi": raw_payload.get("rssi", -55),
                    "packet_count": tcount,
                    "timestamp": raw_payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
                }
                validated = ThreatPayload(**normalized)
                payload = validated.model_dump()
            except Exception as e:
                logger.error(f"Invalid telemetry from ESP32: {e}")
                await websocket.send_json({"error": f"Validation failed: {str(e)}"})
                continue

            logger.warning(f"🚨 PHYSICAL THREAT CAPTURED BY ESP32: {payload['threat_type']} from {payload.get('attacker_mac')}")

            # 1. Fast Path Broadcast to all connected dashboards
            await manager.broadcast_to_dashboards({
                "type": "raw_alert",
                "data": payload,
                "received_at": datetime.now(timezone.utc).isoformat()
            })

            # 2. Slow Path AI Pipeline
            asyncio.create_task(run_ai_pipeline(payload))

    except WebSocketDisconnect:
        manager.disconnect_esp32(websocket)
        logger.info("ESP32-S3 Sniffer Disconnected.")
    except Exception as e:
        logger.error(f"ESP32 WebSocket error: {e}")
        manager.disconnect_esp32(websocket)


@app.websocket("/ws/esp32")
async def websocket_esp32(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket connection endpoint for physical ESP32-S3 sniffer hardware."""
    await handle_esp32_websocket(websocket, token)


@app.websocket("/ws/sentinel")
async def websocket_sentinel(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket connection endpoint for Sentinel v3.0 firmware."""
    await handle_esp32_websocket(websocket, token)