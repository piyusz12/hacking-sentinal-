@echo off
title Sentinel DevSecOps AI Platform Launcher
color 0A
cls
echo ================================================================
echo  🛡️  SENTINEL DEVSECOPS ^& WI-FI IDS AI PLATFORM v3.5
echo ================================================================
echo.
echo [1/2] Starting Sentinel FastAPI Backend Server (Port 8000)...
start "Sentinel AI Backend [Port 8000]" cmd /k "python main.py"

echo [2/2] Starting Sentinel React Dashboard (Port 5173)...
start "Sentinel UI Dashboard [Port 5173]" cmd /k "cd sentinel-ui && npm run dev"

echo.
echo ================================================================
echo  ✅ All Sentinel Services Dispatched!
echo  - Backend API:       http://localhost:8000
echo  - Swagger Docs:      http://localhost:8000/docs
echo  - React Dashboard:   http://localhost:5173
echo ================================================================
echo.
pause
