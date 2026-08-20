"""
Threat detection and simulation router
Handles threat alerts, simulations, and history
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from fastapi.responses import JSONResponse

from backend_server.config import settings
from backend_server.exceptions import (
    ValidationError,
    ThreatAnalysisError,
    RateLimitError,
    ThreatSimulationError,
    InvalidFrameDataError
)
from backend_server.models.schemas import (
    ThreatAlert, ThreatSimulationRequest, ThreatInfo, 
    ThreatListResponse, ThreatSeverity, ThreatType
)
from backend_server.services.ai_engine import ai_engine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threats", tags=["threats"])

# In-memory threat storage (to be replaced with database)
threat_history: List[Dict[str, Any]] = []
active_simulations: Dict[str, bool] = {}


@router.post("/alert")
async def receive_threat_alert(alert: ThreatAlert):
    """Receive threat alert from ESP32 hardware"""
    try:
        threat_id = str(uuid4())
        threat_record = {
            "id": threat_id,
            **alert.model_dump(),
            "ai_analyzed": False,
            "mitigation": None
        }
        
        # Add to history with limit
        threat_history.insert(0, threat_record)
        if len(threat_history) > settings.threat_history_limit:
            threat_history.pop()
        
        # Trigger AI analysis in background
        asyncio.create_task(analyze_threat_async(threat_record))
        
        return {"success": True, "threat_id": threat_id}
    except InvalidFrameDataError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process alert: {str(e)}")


async def analyze_threat_async(threat_record: Dict[str, Any]):
    """Analyze threat with AI engine in background"""
    try:
        analysis = await ai_engine.analyze_threat(threat_record)
        threat_record["ai_analyzed"] = True
        threat_record["analysis"] = analysis
        threat_record["mitigation"] = "\n".join(analysis.get("mitigation_steps", []))
        
        logger.info(f"Threat {threat_record['id']} analyzed: {analysis['confidence_score']}")
    except Exception as e:
        logger.error(f"AI analysis failed for threat {threat_record['id']}: {e}")
        threat_record["ai_analyzed"] = False


@router.post("/simulate")
async def simulate_threat(request: ThreatSimulationRequest, background_tasks: BackgroundTasks):
    """Simulate a network attack for testing"""
    try:
        simulation_id = str(uuid4())
        active_simulations[simulation_id] = True
        
        # Calculate packet parameters based on intensity
        intensity_multipliers = {"low": 10, "medium": 50, "high": 150, "extreme": 500}
        packets_per_second = intensity_multipliers.get(request.intensity, 50)
        
        background_tasks.add_task(
            run_simulation,
            simulation_id,
            request.threat_type,
            request.target_mac,
            request.duration_seconds,
            packets_per_second
        )
        
        return {
            "success": True,
            "simulation_id": simulation_id,
            "message": f"Starting {request.threat_type.value} simulation for {request.duration_seconds}s"
        }
    except Exception as e:
        raise ThreatSimulationError(str(e))


async def run_simulation(
    simulation_id: str,
    threat_type: ThreatType,
    target_mac: Optional[str],
    duration: int,
    pps: int
):
    """Run threat simulation and generate fake packets"""
    try:
        end_time = datetime.utcnow() + timedelta(seconds=duration)
        packet_count = 0
        
        # Map threat type enum properly
        threat_type_map = {
            "deauth": "DEAUTH_STORM",
            "beacon_flood": "BEACON_SPAM", 
            "probe_flood": "PROBE_FLOOD",
            "evil_twin": "EVIL_TWIN",
            "krack": "CUSTOM",
            "unknown": "CUSTOM"
        }
        sim_type_str = threat_type_map.get(threat_type.value, "CUSTOM")
        sim_threat_type = getattr(ThreatType, sim_type_str, ThreatType.UNKNOWN)
        
        # Trigger ESP32 hardware buzzer for this simulation
        from backend_server.main import manager
        await manager.broadcast_to_esp32({
            "type": "simulate_alert",
            "threat_type": sim_type_str,
            "mac": "SIMULATED:AA:BB:CC:DD:EE",
            "rssi": -42,
            "channel": 6,
            "packet_count": pps
        })
        
        while datetime.utcnow() < end_time and active_simulations.get(simulation_id):
            
            # Generate simulated threat data
            simulated_threat = ThreatAlert(
                threat_type=sim_threat_type,
                severity=ThreatSeverity.HIGH if pps > 100 else ThreatSeverity.MEDIUM,
                source_mac="SIMULATED:AA:BB:CC:DD:EE",
                target_mac=target_mac or "FF:FF:FF:FF:FF:FF",
                packet_count=pps,
                packets_per_second=float(pps),
                frame_samples=[]
            )
            
            # Process as real threat
            threat_record = {
                "id": str(uuid4()),
                **simulated_threat.model_dump(),
                "ai_analyzed": False,
                "mitigation": None,
                "simulated": True
            }
            
            threat_history.insert(0, threat_record)
            if len(threat_history) > settings.threat_history_limit:
                threat_history.pop()
            
            packet_count += pps
            await asyncio.sleep(1)
        
        active_simulations.pop(simulation_id, None)
        logger.info(f"Simulation {simulation_id} completed: {packet_count} packets generated")
        
    except Exception as e:
        logger.error(f"Simulation {simulation_id} failed: {e}")
        active_simulations.pop(simulation_id, None)


@router.get("")
async def get_threats(
    limit: int = Query(default=50, ge=1, le=200),
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    ai_analyzed: Optional[bool] = None
):
    """Get threat history with optional filtering"""
    filtered = threat_history[:limit]
    
    if threat_type:
        filtered = [t for t in filtered if t.get('threat_type') == threat_type]
    if severity:
        filtered = [t for t in filtered if t.get('severity') == severity]
    if ai_analyzed is not None:
        filtered = [t for t in filtered if t.get('ai_analyzed') == ai_analyzed]
    
    return ThreatListResponse(
        threats=[ThreatInfo(**t) for t in filtered],
        total_count=len(threat_history),
        filtered_count=len(filtered)
    )


@router.delete("")
async def clear_threats():
    """Clear all threat history"""
    threat_history.clear()
    return {"success": True, "message": "Threat history cleared"}


@router.get("/{threat_id}")
async def get_threat(threat_id: str):
    """Get specific threat details"""
    for threat in threat_history:
        if threat["id"] == threat_id:
            return ThreatInfo(**threat)
    raise HTTPException(status_code=404, detail="Threat not found")
