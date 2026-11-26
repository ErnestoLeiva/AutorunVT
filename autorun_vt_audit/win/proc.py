"""Windows helpers to run CLIs without flashing a console window."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from typing import Any

CREATE_NO_WINDOW = 0x08000000


class ScanCancelled(Exception):
    """User hit Cancel during a long-running scan step."""


def _apply_hidden(kw: dict[str, Any]) -> dict[str, Any]:
    out = dict(kw)
    if os.name == "nt":
        out["creationflags"] = out.get("creationflags", 0) | CREATE_NO_WINDOW
        if "startupinfo" not in out:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0  # SW_HIDE
            out["startupinfo"] = si
    return out


def run_hidden(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    """subprocess.run that does not open a console on Windows."""
    kw = dict(kwargs)
    kw.setdefault("capture_output", True)
    kw.setdefault("check", False)
    return subprocess.run(cmd, **_apply_hidden(kw))


def run_hidden_cancellable(
    cmd: list[str],
    *,
    stop_flag: Callable[[], bool] | None = None,
    poll_sec: float = 0.2,
) -> subprocess.CompletedProcess[bytes]:
    """
    Like run_hidden, but polls stop_flag and kills the child if Cancel is pressed.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **_apply_hidden({}),
    )
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=poll_sec)
                return subprocess.CompletedProcess(cmd, proc.returncode or 0, out, err)
            except subprocess.TimeoutExpired:
                if stop_flag and stop_flag():
                    proc.kill()
                    try:
                        proc.communicate(timeout=3)
                    except Exception:
                        pass
                    raise ScanCancelled("Cancelled.") from None
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.communicate(timeout=3)
            except Exception:
                pass


def popen_hidden(cmd: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
    """subprocess.Popen without a console window (1Password GUI unlock still works)."""
    kw = dict(kwargs)
    kw.setdefault("stdin", subprocess.DEVNULL)
    kw.setdefault("stdout", subprocess.DEVNULL)
    kw.setdefault("stderr", subprocess.DEVNULL)
    return subprocess.Popen(cmd, **_apply_hidden(kw))
