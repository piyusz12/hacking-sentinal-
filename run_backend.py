"""
Sentinel DevSecOps & Wi-Fi IDS AI Platform — Python Launcher
"""

import sys
import subprocess
import uvicorn

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

if __name__ == "__main__":
    print("=" * 60)
    print(" 🛡️  SENTINEL DEVSECOPS & WI-FI IDS AI PLATFORM v3.5")
    print("=" * 60)
    print(" Starting FastAPI Server on http://localhost:8000 ...")
    print(" Swagger API Docs:          http://localhost:8000/docs")
    print(" Dashboard WebSocket:       ws://localhost:8000/ws/dashboard")
    print(" ESP32 Hardware WebSocket:  ws://localhost:8000/ws/esp32")
    print("=" * 60)
    
    uvicorn.run(
        "backend_server.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
