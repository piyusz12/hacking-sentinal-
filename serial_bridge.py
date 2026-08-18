"""
Sentinel ESP32 Hardware Serial-to-WebSocket Bridge
===================================================
Connects to ESP32-S3 over USB Serial (e.g. COM3/COM4 on Windows, /dev/ttyUSB0 on Linux)
and streams raw 802.11 threat frames to the Sentinel FastAPI backend via WebSocket.

Usage:
    python serial_bridge.py
    or with arguments:
    python serial_bridge.py --port COM3 --baud 115200 --ws ws://localhost:8000/ws/esp32
"""

import sys
import json
import asyncio
import argparse
try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False
    serial = None
import websockets

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def find_esp32_port():
    if not SERIAL_AVAILABLE or serial is None:
        return "COM3"
    ports = list(serial.tools.list_ports.comports())
    for p in ports:
        desc = p.description.lower()
        if "ch340" in desc or "cp210" in desc or "usb" in desc or "uart" in desc or "esp32" in desc:
            return p.device
    if ports:
        return ports[0].device
    return "COM3"

async def bridge_loop(port: str, baud: int, ws_url: str):
    print("=" * 60)
    print(" 🛡️ Sentinel ESP32 Hardware Serial-to-WebSocket Bridge")
    print(f" Port:    {port} @ {baud} baud")
    print(f" Target:  {ws_url}")
    print("=" * 60)

    if not SERIAL_AVAILABLE:
        print("❌ Error: 'pyserial' package is not installed. Run 'pip install pyserial' to enable USB bridge.")
        return

    while True:
        try:
            print(f"Connecting to ESP32 on {port}...")
            ser = serial.Serial(port, baud, timeout=1)
            print(f"✅ Serial connected to {port}. Connecting to Sentinel WebSocket...")

            async with websockets.connect(ws_url) as ws:
                print("✅ Connected to Sentinel FastAPI Backend! Listening for ESP32 frames & claps...\n")
                while True:
                    if ser.in_waiting > 0:
                        line = ser.readline().decode("utf-8", errors="ignore").strip()
                        if line:
                            # If line is JSON threat payload
                            if line.startswith("{") and ("threat_type" in line or "type" in line):
                                print(f"🚨 [ESP32 THREAT] Forwarding to AI Pipeline: {line}")
                                await ws.send(line)
                            elif "[MIC]" in line or "[VOICE]" in line:
                                print(f"🎤 [ESP32 VOICE] {line}")
                                await ws.send(json.dumps({"type": "voice_command", "raw": line}))
                            else:
                                print(f"📡 [ESP32 LOG] {line}")
                    await asyncio.sleep(0.005)

        except serial.SerialException as se:
            print(f"⚠️ Serial Port Error ({port}): {se}. Retrying in 3 seconds...")
            await asyncio.sleep(3)
        except (websockets.exceptions.WebSocketException, ConnectionRefusedError) as we:
            print(f"⚠️ WebSocket Error (Backend unavailable): {we}. Retrying in 3 seconds...")
            await asyncio.sleep(3)
        except Exception as e:
            print(f"⚠️ Unexpected error: {e}. Retrying in 3 seconds...")
            await asyncio.sleep(3)

def main():
    parser = argparse.ArgumentParser(description="Sentinel ESP32 Serial Bridge")
    parser.add_argument("--port", default=None, help="ESP32 COM Port (e.g. COM3 or /dev/ttyUSB0)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--ws", default="ws://localhost:8000/ws/esp32?token=sentinel-dev-token-change-me", help="Backend WS URL")
    args = parser.parse_args()

    port = args.port or find_esp32_port()
    try:
        asyncio.run(bridge_loop(port, args.baud, args.ws))
    except KeyboardInterrupt:
        print("\n🛑 Bridge stopped by user.")

if __name__ == "__main__":
    main()
