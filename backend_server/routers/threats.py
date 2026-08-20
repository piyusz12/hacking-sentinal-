"""
Threats router for Sentinel DevSecOps Platform.
Handles threat detection, simulation, and history endpoints.
"""

import asyncio
import csv
import io
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from backend_server.config import settings
from backend_server.exceptions import (
    ValidationError,
    ThreatAnalysisError,
    RateLimitError,
)
from backend_server.models.schemas import (
    ThreatType,
    ThreatSeverity,
    ThreatSimulationRequest,
    ThreatInfo,
    ThreatListResponse,
    ActionResponse,
)

# Router instance
router = APIRouter(prefix="/api/threats", tags=["threats"])
logger = logging.getLogger(__name__)

# In-memory storage (will be replaced with database)
threat_history: List[Dict[str, Any]] = []
total_threats_detected = 0


class ThreatSimulationPayload(BaseModel):
    threat_type: str = Field(default="DEAUTH_STORM")
    attacker_mac: Optional[str] = Field(default="DE:AD:BE:EF:00:01")
    target_mac: Optional[str] = Field(default="FF:FF:FF:FF:FF:FF")
    channel: Optional[int] = Field(default=6, ge=1, le=14)
    rssi: Optional[int] = Field(default=-42, ge=-100, le=0)
    packet_count: Optional[int] = Field(default=1850, ge=1)
    intensity: Optional[Literal["low", "medium", "high"]] = Field(default=None)


def normalize_threat_type(threat_type: str) -> str:
    threat_type_upper = threat_type.upper()
    if "DEAUTH" in threat_type_upper:
        return ThreatType.DEAUTH.value
    if "BEACON" in threat_type_upper:
        return ThreatType.BEACON_FLOOD.value
    if "PROBE" in threat_type_upper:
        return ThreatType.PROBE_FLOOD.value
    if "EVIL" in threat_type_upper and "TWIN" in threat_type_upper:
        return ThreatType.EVIL_TWIN.value
    if "KRACK" in threat_type_upper:
        return ThreatType.KRACK.value
    return ThreatType.UNKNOWN.value


def calculate_severity(threat_type: str, packet_count: int, rssi: int) -> str:
    """Calculate threat severity based on type and intensity."""
    threat_type_upper = threat_type.upper()
    
    if "DEAUTH" in threat_type_upper or "KRACK" in threat_type_upper:
        if packet_count > 1000:
            return ThreatSeverity.CRITICAL.value
        elif packet_count > 500:
            return ThreatSeverity.HIGH.value
        else:
            return ThreatSeverity.MEDIUM.value
    
    if "BEACON_FLOOD" in threat_type_upper or "PROBE_FLOOD" in threat_type_upper:
        if packet_count > 2000:
            return ThreatSeverity.HIGH.value
        elif packet_count > 1000:
            return ThreatSeverity.MEDIUM.value
        else:
            return ThreatSeverity.LOW.value
    
    if "EVIL_TWIN" in threat_type_upper:
        return ThreatSeverity.HIGH.value
    
    return ThreatSeverity.MEDIUM.value


@router.get("", response_model=ThreatListResponse)
async def get_threats(
    limit: int = Query(default=50, ge=1, le=200, description="Maximum threats to return"),
    threat_type: Optional[ThreatType] = Query(default=None, description="Filter by threat type"),
    severity: Optional[ThreatSeverity] = Query(default=None, description="Filter by severity"),
):
    """
    Retrieve threat history with optional filtering.
    
    Returns paginated list of detected threats with metadata.
    """
    filtered = threat_history.copy()
    
    if threat_type:
        filtered = [t for t in filtered if t.get("threat_type") == threat_type.value]
    
    if severity:
        filtered = [t for t in filtered if t.get("severity") == severity.value]
    
    # Sort by timestamp descending and apply limit
    filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    filtered = filtered[:limit]
    
    return ThreatListResponse(
        threats=[ThreatInfo(**t) for t in filtered],
        total_count=len(threat_history),
        filtered_count=len(filtered)
    )


@router.get("/recent", response_model=List[ThreatInfo])
async def get_recent_threats(count: int = Query(default=10, ge=1, le=50)):
    """Get most recent threats without full metadata."""
    recent = sorted(threat_history, key=lambda x: x.get("timestamp", ""), reverse=True)[:count]
    return [ThreatInfo(**t) for t in recent]


@router.post("/simulate", response_model=ActionResponse)
async def simulate_threat(
    request: ThreatSimulationRequest,
    background_tasks: BackgroundTasks
):
    """
    Simulate a network threat for testing purposes.
    
    Creates a synthetic threat event that flows through the detection pipeline.
    """
    global total_threats_detected
    
    if not settings.enable_threat_simulation:
        raise ValidationError(
            message="Threat simulation is disabled",
            details={"setting": "enable_threat_simulation"}
        )
    
    try:
        # Generate threat payload
        threat_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        severity = calculate_severity(
            threat_type=request.threat_type.value,
            packet_count=100 if request.intensity == "low" else 500 if request.intensity == "medium" else 1500,
            rssi=-50
        )
        
        threat_data = {
            "id": threat_id,
            "timestamp": timestamp,
            "threat_type": request.threat_type.value,
            "severity": severity,
            "source_mac": request.target_mac or "DE:AD:BE:EF:00:01",
            "target_mac": request.target_mac or "FF:FF:FF:FF:FF:FF",
            "channel": 6,
            "signal_strength": -50,
            "description": f"Simulated {request.threat_type.value} attack at intensity {request.intensity}",
            "mitigation": None,
            "ai_analyzed": False,
            "simulated": True
        }
        
        # Add to history
        threat_history.append(threat_data)
        total_threats_detected += 1
        
        # Enforce max history limit
        if len(threat_history) > settings.max_threat_history:
            threat_history.pop(0)
        
        logger.info(f"🚨 Simulated threat: {request.threat_type.value} (ID: {threat_id})")
        
        # Background task: trigger AI analysis if enabled
        if settings.enable_ai_analysis:
            background_tasks.add_task(analyze_threat_async, threat_data)
        
        return ActionResponse(
            success=True,
            message=f"Threat simulated successfully: {request.threat_type.value}",
            data={"threat_id": threat_id, "severity": severity}
        )
        
    except Exception as e:
        logger.error(f"Threat simulation failed: {e}")
        raise ThreatAnalysisError(
            message="Failed to simulate threat",
            details={"error": str(e)}
        )


async def analyze_threat_async(threat_data: Dict[str, Any]):
    """Background task to analyze threat with AI."""
    # This would call the AI engine
    # For now, just mark as analyzed
    threat_data["ai_analyzed"] = True
    threat_data["mitigation"] = "AI analysis pending implementation"


@router.delete("/clear", response_model=ActionResponse)
async def clear_threats():
    """Clear all threat history."""
    global threat_history, total_threats_detected
    
    count = len(threat_history)
    threat_history.clear()
    
    logger.info(f"Cleared {count} threats from history")
    
    return ActionResponse(
        success=True,
        message=f"Cleared {count} threats",
        data={"cleared_count": count}
    )


@router.delete("/{threat_id}", response_model=ActionResponse)
async def delete_threat(threat_id: str):
    """Delete a specific threat by ID."""
    global threat_history
    
    original_count = len(threat_history)
    threat_history = [t for t in threat_history if t.get("id") != threat_id]
    
    if len(threat_history) == original_count:
        raise ValidationError(
            message=f"Threat with ID {threat_id} not found",
            details={"threat_id": threat_id}
        )
    
    return ActionResponse(
        success=True,
        message=f"Deleted threat {threat_id}",
        data={"deleted_id": threat_id}
    )


@router.get("/stats")
async def get_threat_stats():
    """Get threat statistics and analytics."""
    if not threat_history:
        return {
            "total_threats": 0,
            "threats_by_type": {},
            "threats_by_severity": {},
            "last_hour_count": 0
        }
    
    # Calculate statistics
    threats_by_type = {}
    threats_by_severity = {}
    last_hour_count = 0
    
    now = datetime.now(timezone.utc)
    
    for threat in threat_history:
        # Count by type
        ttype = threat.get("threat_type", "UNKNOWN")
        threats_by_type[ttype] = threats_by_type.get(ttype, 0) + 1
        
        # Count by severity
        sev = threat.get("severity", "unknown")
        threats_by_severity[sev] = threats_by_severity.get(sev, 0) + 1
        
        # Count last hour
        try:
            threat_time = datetime.fromisoformat(threat.get("timestamp", ""))
            if (now - threat_time).total_seconds() < 3600:
                last_hour_count += 1
        except (ValueError, TypeError):
            pass
    
    return {
        "total_threats": len(threat_history),
        "total_detected_all_time": total_threats_detected,
        "threats_by_type": threats_by_type,
        "threats_by_severity": threats_by_severity,
        "last_hour_count": last_hour_count
    }
