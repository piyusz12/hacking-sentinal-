"""
Sentinel DevSecOps AI Backend — Entry Point

Usage:
    uvicorn backend_main.bckendmain:app --host 0.0.0.0 --port 8000 --reload

Environment Variables:
    SENTINEL_WS_TOKEN        - WebSocket auth token (default: sentinel-dev-token-change-me)
    SENTINEL_LLM_MODEL       - LLM model name (default: gpt-4o-mini)
    SENTINEL_CORS_ORIGINS    - Comma-separated CORS origins (default: http://localhost:5173,http://localhost:3000)
    SENTINEL_MAX_DASHBOARD   - Max dashboard WebSocket connections (default: 20)
    SENTINEL_MAX_ESP32       - Max ESP32 WebSocket connections (default: 5)
    SENTINEL_MAX_AI_TASKS    - Max concurrent AI pipeline tasks (default: 5)
    SENTINEL_MOCK_AI         - Use mock AI responses (default: true)
    OPENAI_API_KEY           - OpenAI API key (required when SENTINEL_MOCK_AI=false)
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "backend_main.bckendmain:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
