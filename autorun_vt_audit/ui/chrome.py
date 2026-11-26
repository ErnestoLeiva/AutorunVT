"""Windows window chrome helpers (dark title bar, etc.)."""

from __future__ import annotations

import ctypes
import sys


def set_dark_title_bar(window) -> None:
    """
    Ask DWM for a dark title bar (Win10 1809+ / Win11).
    Call after the window is mapped; safe to call more than once.
    """
    if sys.platform != "win32":
        return
    try:
        window.update_idletasks()
        hwnd = int(window.winfo_id())
        user32 = ctypes.windll.user32
        dwmapi = ctypes.windll.dwmapi

        # Prefer the non-client frame HWND (title bar lives there)
        GA_ROOT = 2
        root = user32.GetAncestor(hwnd, GA_ROOT)
        if root:
            hwnd = int(root)
        else:
            get_parent = user32.GetParent
            parent = get_parent(hwnd)
            while parent:
                hwnd = parent
                parent = get_parent(hwnd)

        value = ctypes.c_int(1)
        # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE; 19 = older builds
        applied = False
        for attr in (20, 19):
            hr = dwmapi.DwmSetWindowAttribute(
                hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)
            )
            if hr == 0:
                applied = True
                break

        if applied:
            # Force non-client frame redraw so the bar flips immediately
            SWP_NOSIZE = 0x0001
            SWP_NOMOVE = 0x0002
            SWP_NOZORDER = 0x0004
            SWP_NOACTIVATE = 0x0010
            SWP_FRAMECHANGED = 0x0020
            user32.SetWindowPos(
                hwnd,
                0,
                0,
                0,
                0,
                0,
                SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
            )
        window.update_idletasks()
    except Exception:
        pass
