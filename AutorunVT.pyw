"""Windowed launcher — double-click or: pythonw AutorunVT.pyw"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

runpy.run_module("autorun_vt_audit.autorunvt", run_name="__main__")
