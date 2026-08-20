"""
AI Engine Service - Local Ollama integration with LangGraph workflow
Handles threat analysis, mitigation generation, and chat interactions
"""
import asyncio
import time
from typing import Dict, List, Optional, Any, TypedDict
from datetime import datetime

import httpx

from backend_server.core.config import get_settings
from backend_server.core.exceptions import AIPipelineError, VectorDatabaseError
from backend_server.models.schemas import ThreatSeverity, ThreatType

settings = get_settings()


class AgentState(TypedDict):
    """LangGraph agent state"""
    threat_data: Dict[str, Any]
    context: List[str]
    analysis: str
    mitigation: str
    confidence: float


class LocalOllamaEngine:
    """High-Performance Local AI Engine powered by Ollama"""
    
    def __init__(self):
        self.host = settings.ollama_host
        self.default_model = settings.ollama_model
        self.vision_model = settings.ollama_vision_model
        self.active_model = self.default_model
        self.max_context_messages = settings.max_context_messages
        self.ai_timeout = settings.ai_timeout_seconds
        self._client: Optional[httpx.AsyncClient] = None
        self._model_available: Optional[bool] = None
        self.request_count = 0
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.host,
                timeout=httpx.Timeout(self.ai_timeout, connect=10.0)
            )
        return self._client
    
    async def check_model_availability(self) -> bool:
        """Check if Ollama model is available"""
        try:
            client = await self._get_client()
            response = await client.get("/api/tags")
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                self._model_available = any(
                    self.default_model in name or self.vision_model in name 
                    for name in model_names
                )
                return self._model_available
            return False
        except Exception:
            self._model_available = False
            return False
    
    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        stream: bool = False
    ) -> Dict[str, Any]:
        """Generate AI response from Ollama"""
        try:
            client = await self._get_client()
            payload = {
                "model": model or self.default_model,
                "messages": messages[-self.max_context_messages:],
                "stream": stream
            }
            
            start_time = time.time()
            response = await client.post("/api/chat", json=payload)
            processing_time = (time.time() - start_time) * 1000
            
            if response.status_code != 200:
                raise AIPipelineError(f"Ollama API error: {response.status_code}")
            
            result = response.json()
            self.request_count += 1
            
            return {
                "message": {
                    "role": "assistant",
                    "content": result.get("message", {}).get("content", "")
                },
                "model_used": result.get("model", self.default_model),
                "processing_time_ms": processing_time,
                "confidence_score": self._calculate_confidence(result)
            }
        except httpx.TimeoutException:
            raise AIPipelineError("AI request timed out")
        except httpx.ConnectError:
            raise AIPipelineError("Cannot connect to Ollama service")
        except Exception as e:
            raise AIPipelineError(f"AI generation failed: {str(e)}")
    
    def _calculate_confidence(self, result: Dict[str, Any]) -> Optional[float]:
        """Calculate confidence score from AI response"""
        # Simple heuristic based on response length and structure
        content = result.get("message", {}).get("content", "")
        if not content:
            return 0.0
        
        # Longer, structured responses tend to be more confident
        length_score = min(len(content) / 500, 1.0) * 0.5
        
        # Check for confidence indicators
        confidence_keywords = ["definitely", "certainly", "clearly", "evidence"]
        uncertainty_keywords = ["might", "could", "possibly", "uncertain"]
        
        content_lower = content.lower()
        keyword_score = (
            sum(1 for kw in confidence_keywords if kw in content_lower) -
            sum(1 for kw in uncertainty_keywords if kw in content_lower)
        )
        keyword_score = max(0, min(keyword_score * 0.1, 0.5))
        
        return round(length_score + keyword_score, 2)
    
    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a network threat and generate assessment"""
        system_prompt = """You are an expert cybersecurity analyst specializing in IEEE 802.11 wireless network security.
Analyze the provided threat data and provide:
1. A clear threat assessment
2. Severity level (LOW/MEDIUM/HIGH/CRITICAL)
3. Attack vector explanation
4. Immediate mitigation steps
5. Long-term prevention recommendations

Be concise but thorough. Use technical terminology appropriate for security professionals."""

        user_message = f"""Threat Detected:
- Type: {threat_data.get('threat_type', 'Unknown')}
- Source MAC: {threat_data.get('source_mac', 'N/A')}
- Target MAC: {threat_data.get('target_mac', 'N/A')}
- Packets per second: {threat_data.get('packets_per_second', 0)}
- Signal strength: {threat_data.get('signal_strength', 'N/A')} dBm
- First seen: {threat_data.get('first_seen', 'N/A')}
- Last seen: {threat_data.get('last_seen', 'N/A')}

Provide a comprehensive security analysis."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
        
        try:
            result = await self.generate_response(messages, model=self.vision_model)
            
            # Parse response to extract structured data
            content = result["message"]["content"]
            
            return {
                "threat_assessment": content,
                "confidence_score": result["confidence_score"],
                "mitigation_steps": self._extract_mitigation_steps(content),
                "cve_references": self._extract_cve_references(content),
                "recommended_actions": self._extract_actions(content)
            }
        except AIPipelineError:
            # Fallback to template response
            return self._generate_fallback_analysis(threat_data)
    
    def _generate_fallback_analysis(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fallback analysis when AI is unavailable"""
        threat_type = threat_data.get('threat_type', 'unknown')
        
        mitigation_map = {
            'deauth_storm': [
                "Enable Management Frame Protection (MFP/802.11w)",
                "Implement MAC address filtering",
                "Use WPA3 encryption",
                "Monitor for rogue access points"
            ],
            'probe_flood': [
                "Disable SSID broadcast on access points",
                "Implement rate limiting on probe responses",
                "Use hidden networks for sensitive systems",
                "Deploy wireless intrusion prevention system"
            ],
            'beacon_spam': [
                "Configure clients to ignore unknown beacons",
                "Implement beacon frame validation",
                "Use certificate-based authentication",
                "Monitor channel utilization"
            ]
        }
        
        return {
            "threat_assessment": f"Detected {threat_type} attack. Immediate action recommended.",
            "confidence_score": 0.5,
            "mitigation_steps": mitigation_map.get(threat_type, ["Isolate affected systems", "Monitor traffic", "Document incident"]),
            "cve_references": [],
            "recommended_actions": ["Block source MAC", "Alert security team", "Capture packets for forensics"]
        }
    
    def _extract_mitigation_steps(self, content: str) -> List[str]:
        """Extract mitigation steps from AI response"""
        steps = []
        lines = content.split('\n')
        capturing = False
        
        for line in lines:
            line = line.strip()
            if any(kw in line.lower() for kw in ['mitigation', 'remediation', 'steps:', 'action:']):
                capturing = True
                continue
            if capturing and line:
                if line.startswith('-') or line.startswith('*') or line[0].isdigit():
                    steps.append(line.lstrip('-*').strip())
                elif len(steps) > 0 and not line.startswith('#'):
                    steps.append(line)
            if capturing and len(steps) >= 5:
                break
        
        return steps[:5] if steps else ["Implement network segmentation", "Enable logging and monitoring"]
    
    def _extract_cve_references(self, content: str) -> List[str]:
        """Extract CVE references from AI response"""
        import re
        cve_pattern = r'CVE-\d{4}-\d+'
        return re.findall(cve_pattern, content)
    
    def _extract_actions(self, content: str) -> List[str]:
        """Extract recommended actions from AI response"""
        actions = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if any(kw in line.lower() for kw in ['recommend', 'action', 'should', 'must']):
                if line.startswith('-') or line.startswith('*'):
                    actions.append(line.lstrip('-*').strip())
        
        return actions[:3] if actions else ["Document the incident", "Review security policies"]
    
    async def chat(self, messages: List[Dict[str, str]], model: Optional[str] = None) -> Dict[str, Any]:
        """Handle general chat conversations"""
        return await self.generate_response(messages, model)
    
    async def close(self):
        """Close HTTP client"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# Global engine instance
ai_engine = LocalOllamaEngine()
