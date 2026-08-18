"""
Sentinel DevSecOps & Wi-Fi IDS AI Backend — Main Entry Point
============================================================

Usage:
    python main.py
    or:
    uvicorn backend_server.main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys
import uvicorn

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"🛡️ Launching Sentinel DevSecOps AI Backend on http://localhost:{port} ...")
    uvicorn.run(
        "backend_server.main:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
    )
