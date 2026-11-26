from __future__ import annotations

import configparser
import os
import sys
from dataclasses import dataclass
from pathlib import Path


def app_root() -> Path:
    """Folder with config.ini — source tree, or next to a frozen portable exe."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    # autorun_vt_audit/core/config.py → repo root
    return Path(__file__).resolve().parents[2]


def resource_root() -> Path:
    """Bundled assets (theme, ico). Onedir: usually ``_internal`` via ``_MEIPASS``."""
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return app_root()


ROOT = app_root()
RES = resource_root()
AZURE_TCL = RES / "vendor" / "azure-ttk-theme" / "azure.tcl"
CONFIG_INI = ROOT / "config.ini"
# Dev: assets/autorunvt.ico — frozen: bundled next to _MEIPASS root
APP_ICON = (
    (RES / "autorunvt.ico")
    if getattr(sys, "frozen", False)
    else (ROOT / "assets" / "autorunvt.ico")
)

# Public VirusTotal API caps (defaults; live values come from overall_quotas)
VT_MAX_PER_MINUTE = 4
VT_MAX_PER_DAY = 500
VT_MAX_PER_MONTH = 15_500
VT_MIN_INTERVAL_SEC = 60.0 / VT_MAX_PER_MINUTE
VT_PARALLEL = 4

DEFAULT_AUTORUNSC = Path(
    r"C:\Program Files (x86)\SysInternals\Autoruns\autorunsc64.exe"
)

_OP_WINGET = Path(os.environ.get("LOCALAPPDATA", "")) / (
    r"Microsoft\WinGet\Packages"
    r"\AgileBits.1Password.CLI_Microsoft.Winget.Source_8wekyb3d8bbwe\op.exe"
)


@dataclass(frozen=True)
class AppSettings:
    app_name: str
    onepassword_enabled: bool
    onepassword_environment_id: str
    onepassword_secret_name: str
    vt_api_key_manual: str


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_settings() -> AppSettings:
    cp = configparser.ConfigParser()
    if CONFIG_INI.is_file():
        cp.read(CONFIG_INI, encoding="utf-8")
    return AppSettings(
        app_name=cp.get("app", "name", fallback="AutorunVT"),
        onepassword_enabled=_truthy(
            cp.get("onepassword", "enabled", fallback="false")
        ),
        onepassword_environment_id=cp.get(
            "onepassword",
            "environment_id",
            fallback="",
        ).strip(),
        onepassword_secret_name=cp.get(
            "onepassword", "secret_name", fallback="VT_API_KEY"
        ).strip()
        or "VT_API_KEY",
        vt_api_key_manual=cp.get("virustotal", "api_key", fallback="").strip(),
    )


# Lazy-ish module defaults (re-read on each load_settings() call from launcher)
_SETTINGS = load_settings()
APP_NAME = _SETTINGS.app_name
OP_ENVIRONMENT_ID = _SETTINGS.onepassword_environment_id
VT_API_KEY_ENV = _SETTINGS.onepassword_secret_name


def find_op() -> Path | None:
    for candidate in (
        Path(os.environ.get("OP_CLI", "")),
        Path(r"C:\Program Files\1Password CLI\op.exe"),
        _OP_WINGET,
    ):
        if candidate and candidate.is_file():
            return candidate
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        exe = Path(folder) / "op.exe"
        if exe.is_file():
            return exe
    return None


def find_autorunsc() -> Path | None:
    env = os.environ.get("AUTORUNSC_PATH")
    if env and Path(env).is_file():
        return Path(env)
    if DEFAULT_AUTORUNSC.is_file():
        return DEFAULT_AUTORUNSC
    return None


SUSPICIOUS_PATH_MARKERS = (
    r"\temp\\",
    r"\tmp\\",
    r"\appdata\local\temp\\",
    r"\downloads\\",
    r"\users\public\\",
)
