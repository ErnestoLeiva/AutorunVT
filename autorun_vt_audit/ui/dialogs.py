"""Dark modal dialogs — pure tk layout (no ttk/tk bg mismatch boxes)."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Literal

from autorun_vt_audit.core.config import APP_ICON
from autorun_vt_audit.ui.chrome import set_dark_title_bar

# Match Azure dark window chrome
_BG = "#333333"
_FG = "#ffffff"
_MUTED = "#cccccc"

Kind = Literal["info", "warning", "error", "question"]

_KIND_ACCENT = {
    "info": "#58a6ff",
    "warning": "#d29922",
    "error": "#f85149",
    "question": "#58a6ff",
}
_KIND_GLYPH = {
    "info": "i",
    "warning": "!",
    "error": "x",
    "question": "?",
}


def _center_on_parent(win: tk.Toplevel, parent: tk.Misc | None) -> None:
    win.update_idletasks()
    w, h = max(win.winfo_reqwidth(), 360), win.winfo_reqheight()
    if parent is not None:
        try:
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            x = px + max(0, (pw - w) // 2)
            y = py + max(0, (ph - h) // 2)
            win.geometry(f"{w}x{h}+{x}+{y}")
            return
        except tk.TclError:
            pass
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")


def _dialog(
    kind: Kind,
    title: str,
    message: str,
    *,
    parent: tk.Misc | None = None,
    buttons: tuple[tuple[str, object], ...],
    default: object | None = None,
) -> object | None:
    root = parent.winfo_toplevel() if parent is not None else None
    win = tk.Toplevel(root)
    win.withdraw()
    win.title(title)
    win.configure(bg=_BG)
    win.resizable(False, False)
    if root is not None:
        win.transient(root)
    if APP_ICON.is_file():
        try:
            win.iconbitmap(default=str(APP_ICON))
        except Exception:
            pass

    result: dict[str, object | None] = {"value": default}

    def finish(value: object) -> None:
        try:
            win.grab_release()
        except tk.TclError:
            pass
        win.destroy()
        result["value"] = value

    body = tk.Frame(win, bg=_BG, padx=20, pady=16)
    body.pack(fill="both", expand=True)

    head = tk.Frame(body, bg=_BG)
    head.pack(fill="x", anchor="w")

    # Simple letter badge — no emoji (emoji fonts often paint their own bg)
    badge = tk.Label(
        head,
        text=_KIND_GLYPH.get(kind, "i"),
        fg=_KIND_ACCENT.get(kind, _FG),
        bg=_BG,
        font=("Segoe UI", 14, "bold"),
        width=2,
        borderwidth=0,
        highlightthickness=0,
    )
    badge.pack(side="left", padx=(0, 8))

    tk.Label(
        head,
        text=title,
        fg=_FG,
        bg=_BG,
        font=("Segoe UI", 11, "bold"),
        borderwidth=0,
        highlightthickness=0,
        anchor="w",
    ).pack(side="left", fill="x", expand=True)

    tk.Label(
        body,
        text=message,
        fg=_MUTED,
        bg=_BG,
        font=("Segoe UI", 10),
        justify="left",
        anchor="w",
        wraplength=400,
        borderwidth=0,
        highlightthickness=0,
    ).pack(fill="x", pady=(14, 18), anchor="w")

    btn_row = tk.Frame(body, bg=_BG)
    btn_row.pack(anchor="e")
    for i, (label, value) in enumerate(buttons):
        style = "Accent.TButton" if i == 0 else "TButton"
        ttk.Button(
            btn_row,
            text=label,
            style=style,
            command=lambda v=value: finish(v),
        ).pack(side="left", padx=(8, 0))
        if i == 0:
            win.bind("<Return>", lambda _e, v=value: finish(v))

    win.protocol("WM_DELETE_WINDOW", lambda: finish(default))
    win.bind("<Escape>", lambda _e: finish(default))

    def _on_map(_event=None) -> None:
        set_dark_title_bar(win)
        # One more tick after DWM sees the frame
        win.after(30, lambda: set_dark_title_bar(win))

    win.bind("<Map>", _on_map)
    _center_on_parent(win, root)
    win.deiconify()
    win.lift()
    set_dark_title_bar(win)
    win.after(10, lambda: set_dark_title_bar(win))
    win.grab_set()
    win.focus_force()
    win.wait_window()
    return result["value"]


def showinfo(title: str, message: str, *, parent: tk.Misc | None = None) -> None:
    _dialog(
        "info",
        title,
        message,
        parent=parent,
        buttons=(("OK", True),),
        default=True,
    )


def showwarning(title: str, message: str, *, parent: tk.Misc | None = None) -> None:
    _dialog(
        "warning",
        title,
        message,
        parent=parent,
        buttons=(("OK", True),),
        default=True,
    )


def showerror(title: str, message: str, *, parent: tk.Misc | None = None) -> None:
    _dialog(
        "error",
        title,
        message,
        parent=parent,
        buttons=(("OK", True),),
        default=True,
    )


def askyesno(title: str, message: str, *, parent: tk.Misc | None = None) -> bool:
    return bool(
        _dialog(
            "question",
            title,
            message,
            parent=parent,
            buttons=(("Yes", True), ("No", False)),
            default=False,
        )
    )
