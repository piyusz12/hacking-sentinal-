"""
Sentinel DevSecOps & Wi-Fi IDS AI Platform — High-Performance Frame Parser Bridge
==================================================================================
Python ctypes interface to native_frame_decoder.dll (.so) with high-speed
zero-copy bitwise decoding fallback.
"""

import os
import sys
import time
import struct
import ctypes
from typing import Dict, Any, Optional, Tuple

# Try loading the native compiled C dynamic library
NATIVE_LIB_PATH = os.path.join(os.path.dirname(__file__), "native_frame_decoder.dll" if sys.platform == "win32" else "native_frame_decoder.so")
NATIVE_AVAILABLE = False
_c_lib = None

class ParsedFrameResultC(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("frame_type", ctypes.c_uint8),
        ("frame_subtype", ctypes.c_uint8),
        ("to_ds", ctypes.c_uint8),
        ("from_ds", ctypes.c_uint8),
        ("is_protected", ctypes.c_uint8),
        ("is_threat", ctypes.c_uint8),
        ("threat_severity", ctypes.c_uint8),
        ("seq_num", ctypes.c_uint16),
        ("receiver_mac", ctypes.c_char * 18),
        ("transmitter_mac", ctypes.c_char * 18),
        ("bssid", ctypes.c_char * 18),
        ("threat_classification", ctypes.c_char * 32),
    ]

try:
    if os.path.exists(NATIVE_LIB_PATH):
        _c_lib = ctypes.CDLL(NATIVE_LIB_PATH)
        _c_lib.decode_80211_frame.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ParsedFrameResultC)
        ]
        _c_lib.decode_80211_frame.restype = ctypes.c_int
        NATIVE_AVAILABLE = True
except Exception:
    NATIVE_AVAILABLE = False


def _format_mac_fast(b: bytes) -> str:
    return f"{b[0]:02X}:{b[1]:02X}:{b[2]:02X}:{b[3]:02X}:{b[4]:02X}:{b[5]:02X}"


def decode_80211_frame(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Decodes raw IEEE 802.11 frame bytes using low-level C engine (or zero-copy struct fallback).
    """
    if len(raw_bytes) < 24:
        return {
            "valid": False,
            "error": "Frame too short (< 24 bytes 802.11 header)",
            "threat_classification": "INVALID_FRAME"
        }

    # Fast Path: Native C execution
    if NATIVE_AVAILABLE and _c_lib:
        result_c = ParsedFrameResultC()
        ret = _c_lib.decode_80211_frame(raw_bytes, len(raw_bytes), ctypes.byref(result_c))
        if ret == 0:
            return {
                "valid": True,
                "engine": "native_c_accelerated",
                "frame_type": result_c.frame_type,
                "frame_subtype": result_c.frame_subtype,
                "to_ds": bool(result_c.to_ds),
                "from_ds": bool(result_c.from_ds),
                "is_protected": bool(result_c.is_protected),
                "is_threat": bool(result_c.is_threat),
                "threat_severity": result_c.threat_severity,
                "seq_num": result_c.seq_num,
                "receiver_mac": result_c.receiver_mac.decode("ascii", errors="ignore"),
                "transmitter_mac": result_c.transmitter_mac.decode("ascii", errors="ignore"),
                "bssid": result_c.bssid.decode("ascii", errors="ignore"),
                "threat_classification": result_c.threat_classification.decode("ascii", errors="ignore"),
            }

    # Fallback: High-Speed Python Struct / Bitwise Decoder
    fc, duration, a1_0, a1_1, a1_2, a1_3, a1_4, a1_5, \
    a2_0, a2_1, a2_2, a2_3, a2_4, a2_5, \
    a3_0, a3_1, a3_2, a3_3, a3_4, a3_5, seq_ctrl = struct.unpack_from("<HH6B6B6BH", raw_bytes, 0)

    ftype = (fc >> 2) & 0x03
    fsubtype = (fc >> 4) & 0x0F
    to_ds = bool((fc >> 8) & 0x01)
    from_ds = bool((fc >> 9) & 0x01)
    is_protected = bool((fc >> 14) & 0x01)
    seq_num = (seq_ctrl >> 4) & 0x0FFF

    rec_mac = f"{a1_0:02X}:{a1_1:02X}:{a1_2:02X}:{a1_3:02X}:{a1_4:02X}:{a1_5:02X}"
    tx_mac = f"{a2_0:02X}:{a2_1:02X}:{a2_2:02X}:{a2_3:02X}:{a2_4:02X}:{a2_5:02X}"
    bssid_mac = f"{a3_0:02X}:{a3_1:02X}:{a3_2:02X}:{a3_3:02X}:{a3_4:02X}:{a3_5:02X}"

    classification = "STANDARD_80211_FRAME"
    is_threat = False
    severity = 1

    if ftype == 0:  # Management
        if fsubtype == 0x0C:
            classification = "DEAUTH_STORM"
            is_threat = True
            severity = 5
        elif fsubtype == 0x0A:
            classification = "DISASSOC_FLOOD"
            is_threat = True
            severity = 4
        elif fsubtype == 0x08:
            classification = "BEACON_FRAME"
            severity = 1
        elif fsubtype == 0x04:
            classification = "PROBE_REQUEST"
            severity = 2
        elif fsubtype == 0x05:
            classification = "PROBE_RESPONSE"
            severity = 2
        elif fsubtype == 0x0B:
            classification = "AUTH_TRANSACTION"
            severity = 2

    return {
        "valid": True,
        "engine": "python_fast_struct",
        "frame_type": ftype,
        "frame_subtype": fsubtype,
        "to_ds": to_ds,
        "from_ds": from_ds,
        "is_protected": is_protected,
        "is_threat": is_threat,
        "threat_severity": severity,
        "seq_num": seq_num,
        "receiver_mac": rec_mac,
        "transmitter_mac": tx_mac,
        "bssid": bssid_mac,
        "threat_classification": classification,
    }


class FrameRingBufferPython:
    """High-throughput Python ring buffer with identical API to C ring buffer."""
    def __init__(self, capacity: int = 2048):
        self.capacity = capacity
        self.buffer = [None] * capacity
        self.head = 0
        self.tail = 0
        self.dropped_frames = 0
        self.total_processed = 0

    def push(self, data: bytes) -> bool:
        next_head = (self.head + 1) % self.capacity
        if next_head == self.tail:
            self.dropped_frames += 1
            return False
        self.buffer[self.head] = (data, time.time_ns())
        self.head = next_head
        self.total_processed += 1
        return True

    def pop(self) -> Optional[Tuple[bytes, int]]:
        if self.head == self.tail:
            return None
        item = self.buffer[self.tail]
        self.buffer[self.tail] = None
        self.tail = (self.tail + 1) % self.capacity
        return item

    def count(self) -> int:
        if self.head >= self.tail:
            return self.head - self.tail
        return self.capacity - (self.tail - self.head)
