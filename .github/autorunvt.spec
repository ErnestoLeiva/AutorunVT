# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller onedir spec for portable AutorunVT releases.

Run from the repo root:
    python -m PyInstaller --noconfirm --clean .github/autorunvt.spec
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

# Spec lives in .github/ — repo root is the parent.
ROOT = Path(SPECPATH).resolve().parent
ICON = ROOT / "assets" / "autorunvt.ico"
THEME = ROOT / "vendor" / "azure-ttk-theme"

datas = [
    (str(ICON), "."),
]

# Bundle theme Tcl + widget PNGs (skip nested .git / docs / root screenshots)
if THEME.is_dir():
    for path in THEME.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        if path.suffix.lower() == ".md":
            continue
        if path.parent == THEME and path.suffix.lower() == ".png":
            continue
        rel = path.relative_to(ROOT)
        datas.append((str(path), str(rel.parent).replace("\\", "/")))

a = Analysis(
    [str(ROOT / "autorun_vt_audit" / "autorunvt.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=collect_submodules("autorun_vt_audit"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AutorunVT",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name="AutorunVT",
    strip=False,
    upx=False,
    upx_exclude=[],
)
