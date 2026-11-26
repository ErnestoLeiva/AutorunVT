#!/usr/bin/env python3
"""
AutorunVT starter (prefer root AutorunVT.pyw — no console).

Reads config.ini next to the app / portable exe:
  [onepassword] enabled=true  → op run + Windows Hello
  [onepassword] enabled=false → inject [virustotal] api_key into the process env
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from autorun_vt_audit.core.config import (
    APP_ICON,
    app_root,
    load_settings,
)

ROOT = app_root()
CREATE_NO_WINDOW = 0x08000000
_REEXEC_ENV = "AUTORUNVT_PYTHONW"
READY_FLAG = Path(os.environ.get("TEMP", str(ROOT))) / "autorunvt.ready"


def _launcher_pyw() -> Path:
    """Root AutorunVT.pyw when running from source."""
    candidate = ROOT / "AutorunVT.pyw"
    if candidate.is_file():
        return candidate
    return Path(__file__).resolve()


def _find_op() -> Path | None:
    from autorun_vt_audit.core.config import find_op

    return find_op()


def _pythonw() -> Path:
    exe = Path(sys.executable)
    if exe.name.lower() == "python.exe":
        sibling = exe.with_name("pythonw.exe")
        if sibling.is_file():
            return sibling
    return exe


def _ensure_no_console() -> None:
    if getattr(sys, "frozen", False):
        return
    if os.name != "nt":
        return
    if os.environ.get(_REEXEC_ENV) == "1":
        return
    if Path(sys.executable).name.lower() == "pythonw.exe":
        return
    pyw = _pythonw()
    if pyw.resolve() == Path(sys.executable).resolve():
        return
    env = os.environ.copy()
    env[_REEXEC_ENV] = "1"
    subprocess.Popen(
        [str(pyw), str(_launcher_pyw()), *sys.argv[1:]],
        cwd=str(ROOT),
        env=env,
        creationflags=CREATE_NO_WINDOW,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    raise SystemExit(0)


def _apply_icon(window) -> None:
    if APP_ICON.is_file():
        try:
            window.iconbitmap(default=str(APP_ICON))
        except Exception:
            pass


def _splash(message: str, app_name: str):
    import tkinter as tk

    from autorun_vt_audit.ui.chrome import set_dark_title_bar

    root = tk.Tk()
    root.title(app_name)
    _apply_icon(root)
    root.after(10, lambda: set_dark_title_bar(root))
    root.resizable(False, False)
    root.configure(bg="#2b2b2b")
    frm = tk.Frame(root, bg="#2b2b2b", padx=28, pady=22)
    frm.pack()
    tk.Label(
        frm,
        text=app_name,
        fg="#ffffff",
        bg="#2b2b2b",
        font=("Segoe UI", 12, "bold"),
    ).pack(anchor="w")
    label = tk.Label(
        frm,
        text=message,
        fg="#cccccc",
        bg="#2b2b2b",
        font=("Segoe UI", 10),
        justify="left",
    )
    label.pack(anchor="w", pady=(8, 0))
    root.update_idletasks()
    w, h = max(root.winfo_width(), 360), root.winfo_height()
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.update()
    return root, label


def _mark_ready() -> None:
    try:
        READY_FLAG.write_text(str(time.time()), encoding="utf-8")
    except OSError:
        pass


def _start_gui() -> int:
    _mark_ready()
    # No splash here — the main window withdraws until ready. A brief
    # "Loading UI…" toplevel only looked like an awkward empty popup when
    # 1Password is off and we open the GUI immediately.
    from autorun_vt_audit.ui.gui import main

    main()
    return 0


def _op_child_cmd(settings) -> list[str]:
    """Re-enter this process with --app after `op run` injects secrets."""
    op = _find_op()
    assert op is not None
    base = [
        str(op),
        "run",
        f"--environment={settings.onepassword_environment_id}",
        "--",
    ]
    if getattr(sys, "frozen", False):
        return [*base, sys.executable, "--app"]
    return [*base, str(_pythonw()), str(_launcher_pyw()), "--app"]


def _bootstrap_via_op(settings) -> int:
    from autorun_vt_audit.win.proc import popen_hidden

    try:
        READY_FLAG.unlink(missing_ok=True)
    except OSError:
        pass

    splash, label = _splash(
        "Waiting for 1Password / Windows Hello…\n"
        "Approve the unlock prompt if it appears.",
        settings.app_name,
    )

    if _find_op() is None:
        # GUI shows a proper warning on startup; don't block here on a splash label.
        try:
            splash.destroy()
        except Exception:
            pass
        return _start_gui()

    proc = popen_hidden(_op_child_cmd(settings), cwd=str(ROOT))

    started = time.time()
    while True:
        splash.update()
        if READY_FLAG.exists():
            label.configure(text="Unlocked — opening app…")
            splash.update()
            time.sleep(0.15)
            break
        if proc.poll() is not None:
            label.configure(
                text=(
                    f"1Password launch exited early (code {proc.returncode}).\n"
                    f"Check environment_id and that {settings.onepassword_secret_name} exists."
                )
            )
            splash.update()
            splash.after(4500, splash.destroy)
            splash.mainloop()
            return 1
        elapsed = int(time.time() - started)
        if elapsed >= 1:
            label.configure(
                text=(
                    "Waiting for 1Password / Windows Hello…\n"
                    f"Approve the unlock prompt if it appears. ({elapsed}s)"
                )
            )
        time.sleep(0.05)

    try:
        splash.destroy()
    except Exception:
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    local = "--local" in argv
    app = "--app" in argv

    os.chdir(ROOT)
    settings = load_settings()
    secret = settings.onepassword_secret_name

    if not app:
        _ensure_no_console()

    if not settings.onepassword_enabled and settings.vt_api_key_manual:
        os.environ[secret] = settings.vt_api_key_manual

    if app or local or os.environ.get(secret):
        return _start_gui()

    if settings.onepassword_enabled:
        return _bootstrap_via_op(settings)

    return _start_gui()


if __name__ == "__main__":
    raise SystemExit(main())
