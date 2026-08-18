import os
import sys
import importlib
import subprocess

def test_entrypoint_files_exist():
    workspace = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert os.path.exists(os.path.join(workspace, "main.py"))
    assert os.path.exists(os.path.join(workspace, "run_backend.py"))
    assert os.path.exists(os.path.join(workspace, "start_sentinel.bat"))
    assert os.path.exists(os.path.join(workspace, "serial_bridge.py"))

def test_batch_script_contents():
    workspace = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bat_path = os.path.join(workspace, "start_sentinel.bat")
    with open(bat_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "main.py" in content or "uvicorn" in content
    assert "npm run dev" in content or "sentinel-ui" in content
