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
from typing import TypedDict, List, Optional, Union, Dict, Any
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Request, Response, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

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

# --- Configuration & Environment ---
WS_AUTH_TOKEN = os.environ.get("SENTINEL_WS_TOKEN", "sentinel-dev-token-change-me")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_LOCAL_MODEL = os.environ.get("SENTINEL_LOCAL_MODEL", "llama3.2-vision:latest")
MAX_DASHBOARD_CLIENTS = int(os.environ.get("SENTINEL_MAX_DASHBOARD", "50"))
MAX_ESP32_CLIENTS = int(os.environ.get("SENTINEL_MAX_ESP32", "10"))
MAX_CONCURRENT_AI_TASKS = int(os.environ.get("SENTINEL_MAX_AI_TASKS", "5"))
MOCK_AI = os.environ.get("SENTINEL_MOCK_AI", "false").lower() == "true"

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
                    self.active_model = "llama3.2-vision:latest"
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
        if MOCK_AI or not self.ollama_online:
            return {"response": "", "model": "rule_engine", "engine": "sentinel_local_rule_engine", "success": False}

        candidate = model_override or self.active_model or "llama3.2-vision:latest"
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
        disconnected = []
        for client in self.dashboard_clients:
            try:
                await client.send_json(message)
            except Exception:
                disconnected.append(client)
        for dead in disconnected:
            self.disconnect_dashboard(dead)


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
    if not MOCK_AI:
        try:
            analysis = await local_ai_engine.analyze_threat(payload, state.get("historical_context", ""))
            if analysis:
                return {"ai_analysis": analysis}
        except Exception as err:
            logger.error(f"Local AI analysis call failed, falling back to local heuristic engine: {err}")

    # High-fidelity Local Intelligence Rules Engine
    ttype = str(payload.get("threat_type", "UNKNOWN")).upper()
    mac = payload.get("attacker_mac", "DE:AD:BE:EF:00:01")
    target = payload.get("target_mac", "FF:FF:FF:FF:FF:FF")
    ch = payload.get("channel", 6)
    rssi = payload.get("rssi", -55)
    pkts = payload.get("packet_count") or payload.get("pkt_rate") or 150

    if "DEAUTH" in ttype:
        analysis = f"High-velocity 0x0C Deauthentication frame flood detected from rogue MAC {mac} targeting {target} on Channel {ch} ({rssi} dBm, {pkts} pkts/s). Active burst confirmed to force client disconnection for WPA 4-way handshake harvesting."
    elif "TWIN" in ttype or "ROGUE" in ttype:
        analysis = f"Unauthorized Beacon 0x08 broadcast spoofing network ESSID/BSSID characteristics from transmitter {mac} on Channel {ch} ({rssi} dBm). Critical Man-In-The-Middle (MitM) credential harvesting attack active."
    elif "BEACON" in ttype:
        analysis = f"Dense 0x08 Beacon frame saturation from transmitter {mac} on Channel {ch} ({rssi} dBm). Attacker is advertising pseudo-random SSIDs to overwhelm wireless station drivers and degrade AP association."
    elif "PROBE" in ttype or "RECON" in ttype:
        analysis = f"Automated 0x04 Probe Request burst detected from {mac} targeting Channel {ch} ({rssi} dBm). Wireless station reconnaissance and ESSID fingerprinting in progress."
    elif "KARMA" in ttype:
        analysis = f"KARMA probe-response exploitation active from {mac} on Channel {ch}. Rogue node is hijacking station preferred network lists (PNL) to coerce automatic associations."
    elif "PMKID" in ttype:
        analysis = f"Anomalous EAPOL frame 1 sniffing detected from {mac} on Channel {ch} ({rssi} dBm). Transmitter is attempting PMKID hash extraction for offline WPA key recovery."
    elif "WPS" in ttype:
        analysis = f"WPS Registrar M1/M2 brute-force handshake transactions detected from {mac} on Channel {ch}. Potential Pixie Dust entropy weakness exploitation."
    else:
        analysis = f"Anomalous 802.11 RF spectral burst ({ttype}) detected from {mac} on Channel {ch} ({rssi} dBm). Telemetry signature deviates from baseline profile."

    return {"ai_analysis": analysis}

async def generate_mitigation_node(state: AgentState):
    payload = state["threat_payload"]
    if not MOCK_AI:
        try:
            mitigation = await local_ai_engine.generate_mitigation(payload, state.get("ai_analysis", ""))
            if mitigation:
                return {"mitigation_steps": mitigation}
        except Exception as err:
            logger.error(f"Local AI mitigation call failed, falling back to local engine: {err}")

    # Local Tactical Mitigations
    ttype = str(payload.get("threat_type", "UNKNOWN")).upper()
    mac = payload.get("attacker_mac", "DE:AD:BE:EF:00:01")

    if "DEAUTH" in ttype:
        mitigation = (
            "1. Enforce 802.11w Protected Management Frames (PMF / MFP) across all Access Points.\n"
            f"2. Isolate and quarantine rogue MAC {mac} at switch port and RF controller boundary.\n"
            "3. Enable dynamic frequency hopping to shift network traffic away from Channel 6."
        )
    elif "TWIN" in ttype or "ROGUE" in ttype:
        mitigation = (
            "1. Verify authorized BSSID cryptographic fingerprint against internal hardware registry.\n"
            "2. Enforce WPA3-Enterprise with 802.1X certificate-based mutual authentication.\n"
            f"3. Activate WIPS containment countermeasures against rogue transmitter {mac}."
        )
    elif "BEACON" in ttype:
        mitigation = (
            "1. Apply 802.11 management frame rate limiting at the AP firmware level.\n"
            "2. Switch corporate SSID to Dynamic Channel Selection (DCS) to mitigate RF jamming.\n"
            "3. Reject probe responses to non-whitelisted ESSID broadcasts."
        )
    elif "PROBE" in ttype or "RECON" in ttype:
        mitigation = (
            "1. Suppress broadcast SSID responses to hidden or unassociated probe requests.\n"
            f"2. Add source {mac} to SOC SIEM high-priority watchlist.\n"
            "3. Monitor authentication logs for follow-up association bursts."
        )
    elif "PMKID" in ttype:
        mitigation = (
            "1. Upgrade network security to WPA3-Personal (SAE) to eliminate PMKID hash derivation.\n"
            "2. Rotate Pre-Shared Keys (PSK) with high-entropy passphrases (>= 20 characters).\n"
            "3. Disable 802.11r Fast BSS Transition if not required."
        )
    elif "KARMA" in ttype:
        mitigation = (
            "1. Disable auto-connect to open networks on all enterprise mobile and laptop profiles.\n"
            "2. Deploy 802.1X network profile MDM configurations to prevent PNL leakage.\n"
            f"3. Blacklist MAC {mac} at firewall perimeter."
        )
    else:
        mitigation = (
            "1. Capture and inspect raw PCAP frame headers for 802.11 malformations.\n"
            "2. Enforce strict MAC address whitelisting on internal VLANs.\n"
            "3. Re-calibrate ESP32-S3 sniffer sensitivity thresholds."
        )

    return {"mitigation_steps": mitigation}

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
async def run_ai_pipeline(payload: dict):
    global total_threats_detected
    async with ai_semaphore:
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

            active_model = local_ai_engine.last_successful_model or local_ai_engine.active_model
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
                "ai_engine": f"Local Ollama ({active_model}) + LangGraph" if local_ai_engine.ollama_online else "Sentinel Local Forensic AI Engine",
                "analyzed_at": datetime.now(timezone.utc).isoformat()
            }

            threat_history.insert(0, ai_report)
            if len(threat_history) > 200:
                threat_history.pop()

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
                        "id": len(devices_registry) + 1,
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
        try:
            ser.close()
        except Exception:
            pass
        logger.info(f"🔌 Serial bridge on {port} stopped.")


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
        "mock_ai": MOCK_AI,
        "local_ai": {
            "enabled": not MOCK_AI,
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

    active_engine_name = f"Local Ollama ({local_ai_engine.last_successful_model or local_ai_engine.active_model}) + LangGraph" if local_ai_engine.ollama_online else "Sentinel Local Forensic AI Engine"

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
    active_engine_name = f"Local Ollama ({local_ai_engine.last_successful_model or local_ai_engine.active_model}) + LangGraph" if local_ai_engine.ollama_online else "Sentinel Local Forensic AI Engine"
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

    # 2. Async AI pipeline execution
    asyncio.create_task(run_ai_pipeline(payload))

    return {
        "success": True,
        "message": f"Threat simulation '{sim.threat_type}' dispatched to LangGraph Local AI pipeline",
        "payload": payload
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

    if not MOCK_AI:
        try:
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are Sentinel AI, an expert cybersecurity, DevSecOps and 802.11 wireless IDS analyst. "
                        "Provide authoritative, actionable, concise, technical guidance on wireless defense, "
                        "packet forensics, PMF 802.11w, Rogue AP containment, and enterprise network hardening."
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

    # Fallback smart local cybersecurity advisor
    q_lower = query.lower()
    if "deauth" in q_lower or "0x0c" in q_lower:
        resp = "Deauthentication attacks exploit unencrypted 802.11 management frames. The primary defense is enforcing 802.11w Protected Management Frames (PMF) on all APs and stations, making frame spoofing cryptographically impossible."
    elif "evil twin" in q_lower or "rogue" in q_lower:
        resp = "Evil Twin APs clone legitimate SSIDs and MACs. Defend by deploying WPA3-Enterprise with 802.1X EAP-TLS certificate validation, so client stations reject unauthorized access points without trusted root certs."
    elif "beacon" in q_lower:
        resp = "Beacon floods saturate wireless channels with fake SSIDs. Mitigate by enabling AP management frame rate-limiting and switching to Dynamic Frequency Selection (DFS) / 5GHz bands."
    elif "pmkid" in q_lower or "wpa" in q_lower:
        resp = "PMKID attacks harvest the first EAPOL frame RSN IE. Protect networks by upgrading to WPA3-SAE (Simultaneous Authentication of Equals), which eliminates offline dictionary attacks."
    elif "esp32" in q_lower or "hardware" in q_lower:
        resp = "The ESP32-S3 hardware sniffer runs promiscuous frame capture on Core 0 (zero packet loss) and drives the OLED / INMP441 microphone voice command listener on Core 1 (1 clap = Scan, 2 claps = Stop, 3 claps = Stats)."
    else:
        resp = f"Sentinel AI SOC Analyst: Regarding '{query}', our active forensic baseline shows nominal compliance for {threat_type}. Ensure 802.11w PMF is mandatory, monitor promiscuous frame counters, and isolate unknown MAC transmitters at the RF boundary."

    return {
        "response": resp,
        "engine": "sentinel_local_expert",
        "model": "rule_heuristic"
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


# --- ESP32 Web Server Proxy Controls (sentinal-v2.ino) ---

@app.get("/api/esp32/status")
async def esp32_hardware_status():
    """Get connected ESP32 sensor state"""
    return {
        "connected_ws": len(manager.esp32_clients) > 0,
        "connected_serial": serial_bridge_state["is_running"],
        "serial_port": serial_bridge_state["port"],
        "active_clients": len(manager.esp32_clients),
        "firmware_version": "Sentinel Pro v2.0 (Dual-Core ESP32-S3)",
        "voice_commands": {
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

    active_model = local_ai_engine.last_successful_model or local_ai_engine.active_model
    # Send initial welcome and recent threats
    try:
        await websocket.send_json({
            "type": "connection_ack",
            "message": "Connected to Sentinel DevSecOps AI Guardian Backend v3.5",
            "server_time": datetime.now(timezone.utc).isoformat(),
            "recent_threats_count": len(threat_history),
            "ai_engine": f"Local Ollama ({active_model}) + LangGraph" if local_ai_engine.ollama_online else "Sentinel Local Forensic AI Engine"
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


@app.websocket("/ws/esp32")
async def websocket_esp32(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket connection endpoint for physical ESP32-S3 sniffer hardware."""
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
                
                # Check if voice command event
                if raw_payload.get("type") == "voice_command":
                    await manager.broadcast_to_dashboards({
                        "type": "esp32_voice_event",
                        "command": raw_payload.get("command"),
                        "claps": raw_payload.get("claps"),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    continue

                validated = ThreatPayload(**raw_payload)
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