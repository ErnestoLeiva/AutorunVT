from __future__ import annotations

import os
import threading
import time
import tkinter as tk
from tkinter import ttk

from autorun_vt_audit import __version__
from autorun_vt_audit.core.config import (
    APP_ICON,
    AZURE_TCL,
    VT_API_KEY_ENV,
    find_autorunsc,
    find_op,
    load_settings,
)
from autorun_vt_audit.core.models import AutostartEntry
from autorun_vt_audit.scan.autoruns import (
    filter_vt_candidates,
    run_prescan,
    select_for_vt,
    summarize,
)
from autorun_vt_audit.ui import dialogs
from autorun_vt_audit.ui.chrome import set_dark_title_bar
from autorun_vt_audit.vt.client import RateLimiter, enrich_entries
from autorun_vt_audit.win.proc import ScanCancelled

# View modes for the results table
VIEW_ALL = "All entries"
VIEW_HIDE_MS = "Hide Microsoft-signed"
VIEW_VT_ONLY = "VT candidates only"

_CHUNK = 80  # tree rows per UI tick (keeps Azure/ttk responsive)


class AutorunVTApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self._settings = load_settings()
        self.title(f"{self._settings.app_name} v{__version__}")
        self.geometry("1100x720")
        self.minsize(960, 640)
        if APP_ICON.is_file():
            try:
                self.iconbitmap(default=str(APP_ICON))
            except Exception:
                pass
        self.after(10, lambda: set_dark_title_bar(self))

        self._entries: list[AutostartEntry] = []
        self._busy = False
        self._cancel = False
        self._limiter = RateLimiter()
        self._reload_job: str | None = None
        self._fill_job: str | None = None
        self._stats_cache: dict[str, int] | None = None
        self._prescan_pop: tk.Toplevel | None = None
        self._prescan_pop_closed_at = 0.0

        self.view_mode = tk.StringVar(value=VIEW_VT_ONLY)
        self.vt_unsigned = tk.BooleanVar(value=True)
        self.vt_not_verified = tk.BooleanVar(value=True)
        self.vt_suspicious = tk.BooleanVar(value=True)
        self.vt_other_signed = tk.BooleanVar(value=False)  # Adobe/NVIDIA/etc.
        self.vt_ignore_microsoft = tk.BooleanVar(value=True)
        self.prescan_exclude_ms = tk.BooleanVar(value=False)  # autorunsc -m

        self._apply_azure_dark()
        self.withdraw()  # show only after footer checks finish
        self._build()
        self._center()
        self._run_startup_checks()
        self.deiconify()
        self.lift()
        # After the window is up so dialogs have a real parent
        self.after(50, self._warn_startup_issues)

    def _apply_azure_dark(self) -> None:
        if not AZURE_TCL.is_file():
            dialogs.showwarning(
                "Theme missing",
                f"Azure theme not found:\n{AZURE_TCL}\nUsing default ttk theme.",
                parent=self,
            )
            return
        self.tk.call("source", str(AZURE_TCL))
        self.tk.call("set_theme", "dark")

    def _center(self) -> None:
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2 - 20
        self.geometry(f"+{x}+{y}")

    def _build(self) -> None:
        # Options + footer stay pinned; results/activity live in a drag sash.
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        top = ttk.Frame(self, padding=(12, 8))
        top.grid(row=0, column=0, sticky="ew")
        ttk.Label(
            top, text=self._settings.app_name, font=("Segoe UI", 14, "bold")
        ).pack(side="left", padx=(0, 12))
        ttk.Label(
            top,
            text="Autorun + VirusTotal utility — focused scans on suspicious results",
        ).pack(side="left")

        opts = ttk.LabelFrame(self, text="Scan options", padding=(16, 10))
        opts.grid(row=1, column=0, sticky="ew", padx=16, pady=(8, 6))
        opts.columnconfigure(1, weight=1)

        ttk.Label(opts, text="Table view:").grid(row=0, column=0, sticky="w")
        self.view_combo = ttk.Combobox(
            opts,
            textvariable=self.view_mode,
            values=(VIEW_ALL, VIEW_HIDE_MS, VIEW_VT_ONLY),
            state="readonly",
            width=28,
        )
        self.view_combo.grid(row=0, column=1, sticky="w", padx=8)
        self.view_combo.bind("<<ComboboxSelected>>", lambda _e: self._schedule_reload())

        ttk.Label(opts, text="VT targets:").grid(row=1, column=0, sticky="w", pady=(10, 2))
        targets = ttk.Frame(opts)
        targets.grid(row=1, column=1, sticky="w", pady=(10, 2))
        for text, var in (
            ("Unsigned", self.vt_unsigned),
            ("Not verified", self.vt_not_verified),
            ("Suspicious paths", self.vt_suspicious),
            ("Other signed", self.vt_other_signed),
            ("Ignore Microsoft-signed", self.vt_ignore_microsoft),
        ):
            ttk.Checkbutton(
                targets,
                text=text,
                variable=var,
                style="Switch.TCheckbutton",
                command=self._on_vt_filter_change,
            ).pack(side="left", padx=(0, 14))

        btns = ttk.Frame(opts)
        btns.grid(row=2, column=0, columnspan=2, sticky="w", pady=(12, 0))

        # Prescan + small options trigger (popover — not a native menu)
        prescan_split = ttk.Frame(btns)
        prescan_split.pack(side="left", padx=(0, 8))
        self.prescan_btn = ttk.Button(
            prescan_split,
            text="Run local prescan",
            style="Accent.TButton",
            command=self._start_prescan,
        )
        self.prescan_btn.pack(side="left")
        self.prescan_opts_btn = ttk.Button(
            prescan_split,
            text="…",
            width=3,
            style="Accent.TButton",
            command=self._toggle_prescan_options,
        )
        self.prescan_opts_btn.pack(side="left")

        self.vt_btn = ttk.Button(
            btns, text="Enrich with VirusTotal", command=self._start_vt
        )
        self.vt_btn.pack(side="left", padx=(0, 8))
        self.cancel_btn = ttk.Button(
            btns, text="Cancel", command=self._request_cancel, state="disabled"
        )
        self.cancel_btn.pack(side="left")

        # Clean stats strip (always visible with Scan options)
        ttk.Separator(opts, orient="horizontal").grid(
            row=3, column=0, columnspan=2, sticky="ew", pady=(12, 8)
        )
        self.summary_frame = ttk.Frame(opts)
        self.summary_frame.grid(row=4, column=0, columnspan=2, sticky="ew")
        for c in range(6):
            self.summary_frame.columnconfigure(c, weight=1)
        self._stat_vars = {
            "memory": tk.StringVar(value="—"),
            "showing": tk.StringVar(value="—"),
            "vt": tk.StringVar(value="—"),
            "ms": tk.StringVar(value="—"),
            "unsigned": tk.StringVar(value="—"),
            "not_verified": tk.StringVar(value="—"),
        }
        stat_specs = (
            (0, "In memory", "memory"),
            (1, "Showing", "showing"),
            (2, "VT candidates", "vt"),
            (3, "Microsoft", "ms"),
            (4, "Unsigned", "unsigned"),
            (5, "Not verified", "not_verified"),
        )
        for col, title, key in stat_specs:
            cell = ttk.Frame(self.summary_frame, padding=(4, 0))
            cell.grid(row=0, column=col, sticky="ew")
            ttk.Label(cell, text=title).pack(anchor="w")
            ttk.Label(
                cell, textvariable=self._stat_vars[key], font=("Segoe UI", 11, "bold")
            ).pack(anchor="w")

        # Classic PanedWindow: reliable minsize (ttk paned often ignores it).
        # Azure PNG Treeview is expensive on live resize — not a reload loop.
        split = tk.PanedWindow(
            self,
            orient=tk.VERTICAL,
            sashwidth=6,
            sashrelief=tk.FLAT,
            bg="#2b2b2b",
            bd=0,
            opaqueresize=False,  # lighter live drag; apply size on release
        )
        split.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 6))
        self._split = split

        card = ttk.LabelFrame(split, text="Scan results", padding=8)
        card.rowconfigure(0, weight=1)
        card.columnconfigure(0, weight=1)

        # VT lives in #0 (image pip + text). ttk can't color a single values-column.
        cols = ("category", "entry", "signer", "image", "sha")
        self.tree = ttk.Treeview(
            card, columns=cols, show="tree headings", selectmode="browse"
        )
        style = ttk.Style(self)
        style.configure("Treeview", rowheight=28)
        # Drop the tree expander — it steals space from the VT pip under Azure.
        style.layout(
            "Treeview.Item",
            [
                (
                    "Treeitem.padding",
                    {
                        "sticky": "nswe",
                        "children": [
                            ("Treeitem.image", {"side": "left", "sticky": ""}),
                            ("Treeitem.text", {"side": "left", "sticky": ""}),
                        ],
                    },
                )
            ],
        )
        self.tree.heading("#0", text="VT")
        self.tree.column("#0", width=100, stretch=False, minwidth=72)
        self._vt_pips = self._make_vt_pips()
        # Only stretch Image path — fewer column reflows on every resize tick
        headings = {
            "category": ("Category", 100, False),
            "entry": ("Entry", 170, False),
            "signer": ("Signer", 200, False),
            "image": ("Image path", 340, True),
            "sha": ("SHA-256", 130, False),
        }
        for key, (label, width, stretch) in headings.items():
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, stretch=stretch, minwidth=48)
        scroll_y = ttk.Scrollbar(card, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(card, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")

        log_frame = ttk.LabelFrame(split, text="Activity", padding=8)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log = tk.Text(
            log_frame,
            height=4,
            wrap="word",
            relief="flat",
            bg="#333333",
            fg="#ffffff",
            insertbackground="#ffffff",
        )
        log_scroll = ttk.Scrollbar(
            log_frame, orient="vertical", command=self.log.yview
        )
        self.log.configure(yscrollcommand=log_scroll.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(state="disabled")

        # ~header + one tree row; ~label + one text line + scrollbar chrome
        split.add(card, minsize=96, stretch="always")
        split.add(log_frame, minsize=88, stretch="always")
        # Default ~3:1 bias toward results (after first layout)
        self.after_idle(self._apply_default_split)

        # Bottom chrome — own rows so they never get crushed by the split
        self.progress = ttk.Progressbar(self, mode="indeterminate")
        # progress is gridded only while busy (row 3)

        footer = ttk.Frame(self, padding=(16, 8, 16, 12))
        footer.grid(row=4, column=0, sticky="ew")
        ttk.Separator(footer, orient="horizontal").pack(fill="x", pady=(0, 8))
        self.footer_strip = ttk.Frame(footer)
        self.footer_strip.pack(fill="x")
        for c in range(5):
            self.footer_strip.columnconfigure(c, weight=1)

        self._footer_vars = {
            "autoruns": tk.StringVar(value="—"),
            "op": tk.StringVar(value="—"),
            "key": tk.StringVar(value="—"),
            "day": tk.StringVar(value="—"),
            "month": tk.StringVar(value="—"),
        }
        self._footer_value_labels: dict[str, ttk.Label] = {}
        style = ttk.Style(self)
        style.configure(
            "FooterOK.TLabel", foreground="#3fb950", font=("Segoe UI", 11, "bold")
        )
        style.configure(
            "FooterBad.TLabel", foreground="#f85149", font=("Segoe UI", 11, "bold")
        )
        style.configure(
            "FooterNA.TLabel", foreground="#8b949e", font=("Segoe UI", 11, "bold")
        )
        footer_specs = (
            (0, "Autoruns", "autoruns"),
            (1, "1Password CLI", "op"),
            (2, "VT API key", "key"),
            (3, "VT day left", "day"),
            (4, "VT month left", "month"),
        )
        for col, title, key in footer_specs:
            cell = ttk.Frame(self.footer_strip, padding=(4, 0))
            cell.grid(row=0, column=col, sticky="ew")
            ttk.Label(cell, text=title).pack(anchor="w")
            val = ttk.Label(
                cell,
                textvariable=self._footer_vars[key],
                style="FooterNA.TLabel",
            )
            val.pack(anchor="w")
            self._footer_value_labels[key] = val

        self.minsize(960, 640)

    def _apply_default_split(self) -> None:
        """Initial sash ~75% results / 25% activity (user can drag afterward)."""
        try:
            self.update_idletasks()
            total = int(self._split.winfo_height())
            if total > 200:
                self._split.sash_place(0, 0, int(total * 0.75))
        except tk.TclError:
            pass

    def _close_prescan_options(self) -> None:
        pop = self._prescan_pop
        self._prescan_pop = None
        if pop is not None:
            self._prescan_pop_closed_at = time.monotonic()
            try:
                pop.destroy()
            except tk.TclError:
                pass

    def _pointer_over_prescan_opts(self) -> bool:
        try:
            x, y = self.winfo_pointerxy()
            bx = self.prescan_opts_btn.winfo_rootx()
            by = self.prescan_opts_btn.winfo_rooty()
            bw = self.prescan_opts_btn.winfo_width()
            bh = self.prescan_opts_btn.winfo_height()
            return bx <= x < bx + bw and by <= y < by + bh
        except tk.TclError:
            return False

    def _toggle_prescan_options(self) -> None:
        """Compact Azure-styled popover under the … button (prescan flags only)."""
        if self._prescan_pop is not None:
            try:
                if self._prescan_pop.winfo_exists():
                    self._close_prescan_options()
                    return
            except tk.TclError:
                self._prescan_pop = None
        # FocusOut often destroys the popover before this command runs when the
        # user clicks … again — treat that same click as "close", not "reopen".
        if time.monotonic() - self._prescan_pop_closed_at < 0.25:
            return

        pop = tk.Toplevel(self)
        pop.withdraw()
        pop.overrideredirect(True)
        pop.configure(bg="#2b2b2b")
        pop.transient(self)
        self._prescan_pop = pop

        shell = ttk.Frame(pop, style="Card.TFrame", padding=(12, 10))
        shell.pack(fill="both", expand=True)
        ttk.Label(shell, text="Prescan options", font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 6)
        )
        ttk.Checkbutton(
            shell,
            text="Exclude Microsoft (−m)",
            variable=self.prescan_exclude_ms,
            style="Switch.TCheckbutton",
        ).pack(anchor="w")

        def place() -> None:
            pop.update_idletasks()
            bx = self.prescan_opts_btn.winfo_rootx()
            by = self.prescan_opts_btn.winfo_rooty()
            bh = self.prescan_opts_btn.winfo_height()
            pw = max(pop.winfo_reqwidth(), 220)
            ph = pop.winfo_reqheight()
            pop.geometry(f"{pw}x{ph}+{bx}+{by + bh + 4}")
            pop.deiconify()
            pop.lift()
            set_dark_title_bar(pop)
            pop.focus_force()

        def on_focus_out(_event=None) -> None:
            # Defer so checkbox clicks inside the popover don't dismiss it.
            # Skip entirely when the pointer is on … — toggle owns that click.
            pop.after(80, self._maybe_close_prescan_options)

        pop.bind("<FocusOut>", on_focus_out)
        pop.bind("<Escape>", lambda _e: self._close_prescan_options())
        place()

    def _maybe_close_prescan_options(self) -> None:
        pop = self._prescan_pop
        if pop is None:
            return
        if self._pointer_over_prescan_opts():
            return
        try:
            focused = pop.focus_get()
            cur: tk.Misc | None = focused
            while cur is not None:
                if cur is pop:
                    return
                cur = getattr(cur, "master", None)
        except tk.TclError:
            pass
        self._close_prescan_options()
    def _on_vt_filter_change(self) -> None:
        # VT toggles define the candidate set — jump to that view so the table updates
        if self.view_mode.get() != VIEW_VT_ONLY:
            self.view_mode.set(VIEW_VT_ONLY)
        self._schedule_reload()

    def _schedule_reload(self) -> None:
        if self._reload_job is not None:
            self.after_cancel(self._reload_job)
        self._reload_job = self.after(40, self._reload_table)

    def _log(self, msg: str) -> None:
        def _do() -> None:
            self.log.configure(state="normal")
            self.log.insert("end", msg + "\n")
            # Cap log length — long logs + Text widget = lag
            lines = int(self.log.index("end-1c").split(".")[0])
            if lines > 200:
                self.log.delete("1.0", f"{lines - 150}.0")
            self.log.see("end")
            self.log.configure(state="disabled")

        self.after(0, _do)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        self.prescan_btn.configure(state=state)
        self.prescan_opts_btn.configure(state=state)
        self.vt_btn.configure(state=state)
        self.view_combo.configure(state="disabled" if busy else "readonly")
        self.cancel_btn.configure(state="normal" if busy else "disabled")
        if busy:
            self.progress.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 4))
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.grid_forget()

    def _request_cancel(self) -> None:
        self._cancel = True
        self._log("Cancel requested…")

    def _run_startup_checks(self) -> None:
        """Populate the footer before the window is shown (no 'checking…' flash)."""
        key_ok = bool(os.environ.get(VT_API_KEY_ENV))
        if key_ok:
            # overall_quotas is free — do it now so day/month are ready on first paint
            self._limiter.refresh_quotas()
        self._refresh_status_bar()

    def _warn_startup_issues(self) -> None:
        """One dialog listing missing Autoruns / op CLI / VT key (if any)."""
        s = self._settings
        ar = find_autorunsc()
        op = find_op()
        key_ok = bool(os.environ.get(VT_API_KEY_ENV))
        issues: list[str] = []

        if ar is None:
            issues.append(
                "Autoruns CLI not found (autorunsc64.exe).\n"
                "Install Sysinternals Autoruns, or set AUTORUNSC_PATH to the exe.\n"
                "Default look-up: Program Files (x86)\\SysInternals\\Autoruns\\\n"
                "Local prescan will fail until this is fixed."
            )

        if s.onepassword_enabled and op is None:
            issues.append(
                "1Password is enabled in config.ini, but op.exe was not found.\n"
                "Install the 1Password CLI and ensure it is on PATH "
                "(or under the usual install / WinGet folder).\n"
                "Or set [onepassword] enabled=false and use [virustotal] api_key."
            )

        if s.onepassword_enabled and op is not None and not (s.onepassword_environment_id or "").strip():
            issues.append(
                "1Password is enabled, but environment_id is empty in config.ini.\n"
                "Set [onepassword] environment_id to your 1Password Environment id."
            )

        if not key_ok:
            if s.onepassword_enabled:
                issues.append(
                    f"VirusTotal key ({VT_API_KEY_ENV}) is not in this process.\n"
                    "With 1Password enabled: check environment_id / secret_name, "
                    "install op CLI, and approve Windows Hello when prompted.\n"
                    "Local prescan still works; VT enrichment needs the key."
                )
            else:
                issues.append(
                    "VirusTotal API key is not configured.\n"
                    "In config.ini set [onepassword] enabled=false and "
                    "[virustotal] api_key=…\n"
                    "Or enable 1Password and set environment_id.\n"
                    "Local prescan still works; VT enrichment needs the key."
                )

        if not issues:
            return
        dialogs.showwarning(
            "Setup needed",
            "\n\n".join(issues),
            parent=self,
        )

    def _set_footer_cell(self, key: str, text: str, tone: str) -> None:
        """tone: ok | bad | na"""
        self._footer_vars[key].set(text)
        style = {
            "ok": "FooterOK.TLabel",
            "bad": "FooterBad.TLabel",
            "na": "FooterNA.TLabel",
        }.get(tone, "FooterNA.TLabel")
        lbl = self._footer_value_labels.get(key)
        if lbl is not None:
            lbl.configure(style=style)

    def _refresh_status_bar(self) -> None:
        op = find_op()
        ar = find_autorunsc()
        key_ok = bool(os.environ.get(VT_API_KEY_ENV))
        s = self._settings

        if ar:
            self._set_footer_cell("autoruns", "OK", "ok")
        else:
            self._set_footer_cell("autoruns", "Missing", "bad")

        if not s.onepassword_enabled:
            self._set_footer_cell("op", "N/A", "na")
        elif op:
            self._set_footer_cell("op", "OK", "ok")
        else:
            self._set_footer_cell("op", "Missing", "bad")

        if key_ok:
            self._set_footer_cell("key", "Present", "ok")
        else:
            self._set_footer_cell("key", "Missing", "bad")

        snap = self._limiter.snapshot
        if snap.ok:
            self._set_footer_cell("day", str(snap.daily_remaining), "ok")
            self._set_footer_cell("month", f"{snap.monthly_remaining:,}", "ok")
        elif key_ok:
            self._set_footer_cell("day", "Error", "bad")
            self._set_footer_cell("month", "Error", "bad")
        else:
            self._set_footer_cell("day", "N/A", "na")
            self._set_footer_cell("month", "N/A", "na")

    def _vt_flags(self) -> dict[str, bool]:
        return {
            "unsigned": self.vt_unsigned.get(),
            "not_verified": self.vt_not_verified.get(),
            "suspicious_path": self.vt_suspicious.get(),
            "other_signed": self.vt_other_signed.get(),
            "ignore_microsoft": self.vt_ignore_microsoft.get(),
        }

    def _display_entries(self) -> list[AutostartEntry]:
        mode = self.view_mode.get()
        if mode == VIEW_HIDE_MS:
            return [e for e in self._entries if not e.is_microsoft_verified()]
        if mode == VIEW_VT_ONLY:
            return filter_vt_candidates(self._entries, **self._vt_flags())
        return self._entries

    def _make_vt_pips(self) -> dict[str, tk.PhotoImage]:
        """Tiny solid circles for tree #0 (keep refs to avoid GC)."""

        def dot(color: str, size: int = 14) -> tk.PhotoImage:
            # PPM is reliable on Windows; PhotoImage.put(to=) is easy to get wrong.
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            cx = cy = (size - 1) / 2.0
            rad2 = (size / 2.0 - 0.6) ** 2
            # Match Azure dark tree background so the square doesn't show
            br, bg, bb = 51, 51, 51  # #333333
            pixels = bytearray()
            for y in range(size):
                for x in range(size):
                    if (x - cx) ** 2 + (y - cy) ** 2 <= rad2:
                        pixels.extend((r, g, b))
                    else:
                        pixels.extend((br, bg, bb))
            header = f"P6\n{size} {size}\n255\n".encode("ascii")
            return tk.PhotoImage(data=header + bytes(pixels))

        return {
            "clean": dot("#3fb950"),
            "sus": dot("#d29922"),
            "hit": dot("#f85149"),
            "empty": dot("#6e7681"),
        }

    def _vt_scores(self, e: AutostartEntry) -> tuple[int, int, int]:
        mal = int(e.vt_malicious or 0)
        sus = int(e.vt_suspicious or 0)
        total = int(e.vt_total or 0)
        if total <= 0:
            total = mal + sus + int(e.vt_undetected or 0)
        return mal, sus, total

    def _vt_severity(self, e: AutostartEntry) -> str:
        if e.vt_status != "ok":
            return "empty"
        mal, sus, _total = self._vt_scores(e)
        if mal > 0:
            return "hit"
        if sus > 0:
            return "sus"
        return "clean"

    def _vt_pip(self, e: AutostartEntry) -> tk.PhotoImage:
        return self._vt_pips[self._vt_severity(e)]

    def _vt_cell(self, e: AutostartEntry) -> str:
        """malicious/suspicious/engines — e.g. 0/1/72 (color is the #0 pip)."""
        if e.vt_status != "ok":
            return e.vt_status or ""
        mal, sus, total = self._vt_scores(e)
        return f"{mal}/{sus}/{total}"

    def _row_values(self, e: AutostartEntry) -> tuple[str, ...]:
        sha = (e.sha256 or e.pesha256 or "")[:16]
        return (e.category, e.entry, e.signer, e.image_path, sha)
    def _update_summary_only(self) -> None:
        if not self._entries:
            for key in self._stat_vars:
                self._stat_vars[key].set("—")
            return
        if self._stats_cache is None:
            self._stats_cache = summarize(self._entries)
        stats = self._stats_cache
        shown = len(self._display_entries())
        # VT candidates = scannable rows matching toggles (not the same as in-memory).
        # All category toggles OFF ⇒ every scannable row; Ignore Microsoft still applies.
        vt_n = len(filter_vt_candidates(self._entries, **self._vt_flags()))
        self._stat_vars["memory"].set(str(stats["total"]))
        self._stat_vars["showing"].set(str(shown))
        self._stat_vars["vt"].set(str(vt_n))
        self._stat_vars["ms"].set(str(stats["microsoft_verified"]))
        self._stat_vars["unsigned"].set(
            f"{stats['unsigned_scannable']} / {stats['unsigned']}"
        )
        self._stat_vars["not_verified"].set(str(stats["not_verified"]))

    def _reload_table(self) -> None:
        self._reload_job = None
        if self._fill_job is not None:
            self.after_cancel(self._fill_job)
            self._fill_job = None

        # Clear fast
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)

        rows = self._display_entries()
        self._update_summary_only()
        if not rows:
            return

        # Chunked insert so Azure theme + 1k+ rows don't freeze the UI
        def fill(start: int = 0) -> None:
            end = min(start + _CHUNK, len(rows))
            for e in rows[start:end]:
                self.tree.insert(
                    "",
                    "end",
                    text=self._vt_cell(e),
                    image=self._vt_pip(e),
                    values=self._row_values(e),
                )
            if end < len(rows):
                self._fill_job = self.after(1, lambda: fill(end))
            else:
                self._fill_job = None

        fill(0)

    def _start_prescan(self) -> None:
        if self._busy:
            return
        if find_autorunsc() is None:
            dialogs.showerror(
                "Autoruns not found",
                "autorunsc64.exe was not found.\n\n"
                "Install Sysinternals Autoruns, or set AUTORUNSC_PATH to the full "
                "path of autorunsc64.exe, then try again.",
                parent=self,
            )
            return
        self._close_prescan_options()
        self._cancel = False
        self._set_busy(True)
        use_m = self.prescan_exclude_ms.get()
        flags = "−a * −c −h −s −t" + (" −m" if use_m else "")
        self._log(f"Starting local prescan ({flags})…")

        def worker() -> None:
            try:
                entries = run_prescan(
                    hide_microsoft=use_m,
                    on_progress=lambda m: self._log(m),
                    stop_flag=lambda: self._cancel,
                )
                self._entries = entries
                self._stats_cache = summarize(entries)

                def finish() -> None:
                    self._reload_table()
                    self._refresh_status_bar()
                    total = len(self._entries)
                    vt_n = len(
                        filter_vt_candidates(self._entries, **self._vt_flags())
                    )
                    skipped = total - vt_n
                    msg = f"Prescan complete — {total} in memory, {vt_n} VT-scannable"
                    if skipped:
                        why = "no hashable image"
                        if self.vt_ignore_microsoft.get():
                            why += ", or Ignore Microsoft"
                        msg += f" ({skipped} skipped: {why})"
                    msg += ". View → All entries to see everything."
                    self._log(msg)

                self.after(0, finish)
            except ScanCancelled:
                self._log("Prescan cancelled — previous results kept.")
            except Exception as exc:  # noqa: BLE001
                self._log(f"ERROR: {exc}")
                self.after(
                    0,
                    lambda: dialogs.showerror(
                        "Prescan failed", str(exc), parent=self
                    ),
                )
            finally:
                self.after(0, lambda: self._set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def _vt_key_help(self) -> str:
        s = self._settings
        if s.onepassword_enabled:
            return (
                f"{VT_API_KEY_ENV} is not in this process.\n\n"
                "1Password mode is on — check config.ini:\n"
                f"  • environment_id (now: {s.onepassword_environment_id or '(empty)'})\n"
                f"  • secret_name (now: {s.onepassword_secret_name})\n"
                "Install/fix op.exe on PATH, restart via AutorunVT.pyw, "
                "and approve Windows Hello.\n\n"
                "Or set enabled=false and put the key under [virustotal] api_key."
            )
        return (
            f"{VT_API_KEY_ENV} is not in this process.\n\n"
            "Manual key mode — in config.ini set:\n"
            "  [onepassword] enabled=false\n"
            "  [virustotal] api_key=your_key\n"
            "Then restart AutorunVT.\n\n"
            "Or set enabled=true with a valid 1Password environment_id."
        )

    def _start_vt(self) -> None:
        if self._busy:
            return
        if not self._entries:
            dialogs.showinfo(
                "No data", "Run a local prescan first.", parent=self
            )
            return
        if not os.environ.get(VT_API_KEY_ENV):
            dialogs.showerror(
                "VirusTotal key missing",
                self._vt_key_help(),
                parent=self,
            )
            return

        flags = self._vt_flags()
        targets = select_for_vt(self._entries, **flags)
        if not targets:
            dialogs.showinfo(
                "Nothing to query",
                "No matching hashes for the selected filters.",
                parent=self,
            )
            return

        est_min = (len(targets) * 15) / 60.0
        if not dialogs.askyesno(
            "VirusTotal enrichment",
            f"- {len(targets)} unique hashes will be looked up (hash-only, no upload).\n"
            f"- Public API: ≤4/min, ≤500/day.\n"
            f"- Estimated wait ≈ {est_min:.1f} minutes.\n\nContinue?",
            parent=self,
        ):
            return

        self._cancel = False
        self._set_busy(True)
        self._log(f"VirusTotal: {len(targets)} hashes queued…")

        def worker() -> None:
            try:
                enrich_entries(
                    targets,
                    limiter=self._limiter,
                    on_progress=lambda m: self._log(m),
                    stop_flag=lambda: self._cancel,
                )
                by_hash = {e.best_hash: e for e in targets if e.best_hash}
                for e in self._entries:
                    src = by_hash.get(e.best_hash)
                    if src and src.vt_status:
                        e.vt_status = src.vt_status
                        e.vt_malicious = src.vt_malicious
                        e.vt_suspicious = src.vt_suspicious
                        e.vt_undetected = src.vt_undetected
                        e.vt_total = src.vt_total
                        e.vt_permalink = src.vt_permalink
                self.after(0, self._reload_table)
                self.after(0, self._refresh_status_bar)
                if self._cancel:
                    self._log("VirusTotal enrichment stopped — partial results kept.")
                else:
                    self._log("VirusTotal enrichment finished.")
            except Exception as exc:  # noqa: BLE001
                self._log(f"ERROR: {exc}")
                self.after(
                    0,
                    lambda: dialogs.showerror(
                        "VirusTotal failed", str(exc), parent=self
                    ),
                )
            finally:
                self.after(0, lambda: self._set_busy(False))

        threading.Thread(target=worker, daemon=True).start()


def main() -> None:
    app = AutorunVTApp()
    app.mainloop()
