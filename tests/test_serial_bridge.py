import sys
import argparse
from unittest.mock import patch, MagicMock
import serial_bridge

def test_find_esp32_port():
    mock_serial = MagicMock()
    mock_port1 = MagicMock()
    mock_port1.device = "COM5"
    mock_port1.description = "USB-SERIAL CH340 (COM5)"

    mock_port2 = MagicMock()
    mock_port2.device = "COM1"
    mock_port2.description = "Communications Port (COM1)"
    mock_serial.tools.list_ports.comports.return_value = [mock_port2, mock_port1]

    with patch.object(serial_bridge, "serial", mock_serial), patch.object(serial_bridge, "SERIAL_AVAILABLE", True):
        port = serial_bridge.find_esp32_port()
        assert port == "COM5"

def test_find_esp32_port_fallback():
    mock_serial = MagicMock()
    mock_port = MagicMock()
    mock_port.device = "COM2"
    mock_port.description = "Standard Port"
    mock_serial.tools.list_ports.comports.return_value = [mock_port]

    with patch.object(serial_bridge, "serial", mock_serial), patch.object(serial_bridge, "SERIAL_AVAILABLE", True):
        port = serial_bridge.find_esp32_port()
        assert port == "COM2"

    mock_serial.tools.list_ports.comports.return_value = []
    with patch.object(serial_bridge, "serial", mock_serial), patch.object(serial_bridge, "SERIAL_AVAILABLE", True):
        port = serial_bridge.find_esp32_port()
        assert port == "COM3"

def test_find_esp32_port_when_no_serial():
    with patch.object(serial_bridge, "SERIAL_AVAILABLE", False):
        port = serial_bridge.find_esp32_port()
        assert port == "COM3"

def test_serial_bridge_cli_args():
    test_args = ["serial_bridge.py", "--port", "COM4", "--baud", "9600", "--ws", "ws://localhost:8000/ws/esp32"]
    with patch.object(sys, "argv", test_args):
        parser = argparse.ArgumentParser(description="Sentinel ESP32 Serial Bridge")
        parser.add_argument("--port", default=None)
        parser.add_argument("--baud", type=int, default=115200)
        parser.add_argument("--ws", default="ws://localhost:8000/ws/esp32")
        args = parser.parse_args()
        assert args.port == "COM4"
        assert args.baud == 9600
        assert args.ws == "ws://localhost:8000/ws/esp32"
