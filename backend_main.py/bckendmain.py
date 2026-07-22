# backend_main.py
# Tech Stack: FastAPI (Async WebSockets), LangGraph (AI Agent), LangChain (LLM), FAISS (Vector DB)

import json
import asyncio
import logging
from typing import TypedDict, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

# LangChain & LangGraph Imports
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI # Ya ChatAnthropic use kar sakte ho
from langgraph.graph import StateGraph, END
from langchain_community.vectorstores import FAISS
from langchain_core.embeddings import FakeEmbeddings # Placeholder for Hackathon Demo

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Sentinel-Backend")

app = FastAPI(title="Sentinel DevSecOps AI Backend")

# --- In-Memory Connection Manager for WebSockets ---
class ConnectionManager:
    def __init__(self):
        self.dashboard_clients: List[WebSocket] = []

    async def connect_dashboard(self, websocket: WebSocket):
        await websocket.accept()
        self.dashboard_clients.append(websocket)
        logger.info(f"Dashboard client connected. Total: {len(self.dashboard_clients)}")

    def disconnect_dashboard(self, websocket: WebSocket):
        if websocket in self.dashboard_clients:
            self.dashboard_clients.remove(websocket)

    async def broadcast_to_dashboards(self, message: dict):
        for connection in self.dashboard_clients:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to dashboard: {e}")

manager = ConnectionManager()

# --- Mock Vector DB Setup (FAISS) ---
# Hackathon tip: Hum ek fake DB initialize kar rahe hain demo ke liye.
# Asal mein yahan pichle attacks ke logs hone chahiye.
embeddings = FakeEmbeddings(size=1536)
mock_texts = [
    "DEAUTH_STORM: Usually indicates an attacker trying to disconnect clients to capture WPA handshakes or force them to an Evil Twin.",
    "EVIL_TWIN: A rogue Access Point copying the SSID to intercept traffic."
]
vector_db = FAISS.from_texts(mock_texts, embeddings)

# --- LangGraph Setup ---
# 1. State Definition
class AgentState(TypedDict):
    threat_payload: dict
    historical_context: str
    ai_analysis: str
    mitigation_steps: str

# 2. Nodes
def retrieve_context(state: AgentState):
    logger.info("LangGraph Node: Retrieving historical context from FAISS...")
    threat_type = state["threat_payload"].get("threat_type", "")
    docs = vector_db.similarity_search(threat_type, k=1)
    context = docs[0].page_content if docs else "No historical context found."
    return {"historical_context": context}

def analyze_threat(state: AgentState):
    logger.info("LangGraph Node: Running AI Threat Analysis...")
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.2) # Placeholder LLM
    
    prompt = f"""
    You are a Cybersecurity AI. Analyze this live threat from an ESP32-S3 sensor.
    Payload: {json.dumps(state['threat_payload'])}
    Historical Context: {state['historical_context']}
    
    Provide a short, highly technical 2-sentence analysis of what is happening.
    """
    response = llm.invoke([SystemMessage(content="You are a SOC analyst AI."), HumanMessage(content=prompt)])
    return {"ai_analysis": response.content}

def generate_mitigation(state: AgentState):
    logger.info("LangGraph Node: Generating Mitigation Steps...")
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.1)
    
    prompt = f"""
    Based on this threat: {state['threat_payload']['threat_type']}
    And analysis: {state['ai_analysis']}
    Provide 3 bullet points for immediate network mitigation.
    """
    response = llm.invoke([SystemMessage(content="Provide concise, actionable mitigation steps."), HumanMessage(content=prompt)])
    return {"mitigation_steps": response.content}

# 3. Build Graph
workflow = StateGraph(AgentState)
workflow.add_node("retrieve", retrieve_context)
workflow.add_node("analyze", analyze_threat)
workflow.add_node("mitigate", generate_mitigation)

workflow.set_entry_point("retrieve")
workflow.add_edge("retrieve", "analyze")
workflow.add_edge("analyze", "mitigate")
workflow.add_edge("mitigate", END)

threat_agent = workflow.compile()

# --- FastAPI Routes ---

@app.get("/")
async def root():
    return {"status": "Sentinel Backend is ACTIVE", "version": "1.0"}

# Route for React Dashboard to listen to AI alerts
@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await manager.connect_dashboard(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_dashboard(websocket)

# Route for ESP32-S3 to push raw alerts
@app.websocket("/ws/esp32")
async def websocket_esp32(websocket: WebSocket):
    await websocket.accept()
    logger.info("ESP32-S3 Hardware Connected via WebSocket.")
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            logger.warning(f"🚨 RAW THREAT RECEIVED FROM ESP32: {payload}")
            
            # 1. Immediately forward raw alert to dashboard (Fast Path)
            await manager.broadcast_to_dashboards({"type": "raw_alert", "data": payload})
            
            # 2. Trigger LangGraph AI Pipeline asynchronously (Slow Path)
            asyncio.create_task(run_ai_pipeline(payload))
            
    except WebSocketDisconnect:
        logger.error("ESP32-S3 Disconnected.")
    except json.JSONDecodeError:
        logger.error("Invalid JSON received from hardware.")

# Async function to run LangGraph without blocking the WebSocket
async def run_ai_pipeline(payload: dict):
    logger.info("Initiating LangGraph AI Agentic Workflow...")
    
    # Initialize State
    initial_state = {"threat_payload": payload, "historical_context": "", "ai_analysis": "", "mitigation_steps": ""}
    
    # Run Graph
    # Note: In a real app, ainvoke is used. For this demo we simulate the invoke to avoid actual API keys blocking the code
    try:
        # final_state = await threat_agent.ainvoke(initial_state) # Real implementation
        
        # MOCK IMPLEMENTATION FOR HACKATHON OFFLINE TESTING
        await asyncio.sleep(2) # Simulate AI thinking time
        final_state = {
            "ai_analysis": f"Detected high volume of 0x0C management frames from {payload.get('attacker_mac')}. This is a confirmed 802.11 deauthentication flood targeting network availability.",
            "mitigation_steps": "- Enable 802.11w Protected Management Frames (PMF).\n- Identify and physically locate the rogue transmitter.\n- Temporarily whitelist trusted MAC addresses on the AP."
        }
        
        # Format the AI report
        ai_report = {
            "type": "ai_report",
            "threat": payload.get("threat_type"),
            "analysis": final_state["ai_analysis"],
            "mitigation": final_state["mitigation_steps"]
        }
        
        # Broadcast AI report to React Dashboard
        logger.info("AI Analysis Complete. Broadcasting to Dashboard.")
        await manager.broadcast_to_dashboards(ai_report)
        
    except Exception as e:
        logger.error(f"AI Pipeline failed: {e}")