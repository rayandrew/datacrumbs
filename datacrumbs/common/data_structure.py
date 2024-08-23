import ctypes
from typing import Any, Dict


class DFEvent:
    pid: int
    tid: int
    name: str
    cat: str
    ts: float
    args: Dict[str, Any]


class Filename(ctypes.Structure):
    _fields_ = [
        ("fname", ctypes.c_char * 256),
    ]
