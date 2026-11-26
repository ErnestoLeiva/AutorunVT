"""Fill missing hashes / signers so VT filters match reality."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path

from autorun_vt_audit.core.models import AutostartEntry
from autorun_vt_audit.win.proc import ScanCancelled, run_hidden_cancellable

StopFlag = Callable[[], bool]


def _existing_path(image_path: str) -> Path | None:
    p = (image_path or "").strip()
    if not p or p.lower().startswith("file not found"):
        return None
    path = Path(p)
    if path.is_file():
        return path

    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    # Autoruns sometimes emits system32\... without a drive
    alt = root / p
    if alt.is_file():
        return alt

    # Known-DLL rows often point at SysWOW64 copies that aren't real files;
    # the native image usually lives in System32 (and vice versa).
    name = path.name
    for folder in ("System32", "SysWOW64"):
        candidate = root / folder / name
        if candidate.is_file():
            return candidate
    return None


def _sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _authenticode_batch(
    paths: list[Path],
    *,
    stop_flag: StopFlag | None = None,
) -> dict[str, str]:
    """
    One PowerShell pass → map path.lower() -> Autoruns-like signer string.
    Hidden window; returns {} on failure. Raises ScanCancelled if stopped.
    """
    if not paths:
        return {}
    if stop_flag and stop_flag():
        raise ScanCancelled("Cancelled.")
    # JSON list keeps paths with spaces/unicode safe
    payload = json.dumps([str(p) for p in paths], ensure_ascii=False)
    ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
$paths = ConvertFrom-Json -InputObject @'
{payload}
'@
$out = foreach ($p in $paths) {{
  if (-not (Test-Path -LiteralPath $p)) {{ continue }}
  $sig = Get-AuthenticodeSignature -LiteralPath $p
  $status = [string]$sig.Status
  $subject = ''
  if ($sig.SignerCertificate) {{ $subject = [string]$sig.SignerCertificate.Subject }}
  # CN=Foo, O=Bar → prefer CN
  $cn = $subject
  if ($subject -match 'CN=([^,]+)') {{ $cn = $Matches[1].Trim() }}
  $signer = ''
  if ($status -eq 'Valid' -and $cn) {{
    $signer = "(Verified) $cn"
  }} elseif ($status -eq 'NotSigned' -or -not $cn) {{
    $signer = ''
  }} else {{
    $signer = "(Not verified) $cn"
  }}
  [pscustomobject]@{{ Path = $p; Signer = $signer; Status = $status }}
}}
$out | ConvertTo-Json -Compress
"""
    proc = run_hidden_cancellable(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps,
        ],
        stop_flag=stop_flag,
    )
    if not proc.stdout:
        return {}
    try:
        text = proc.stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return {}
        data = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if isinstance(data, dict):
        data = [data]
    result: dict[str, str] = {}
    for row in data:
        path = str(row.get("Path") or "")
        signer = str(row.get("Signer") or "")
        if path:
            result[path.lower()] = signer
    return result


def finalize_entries(
    entries: list[AutostartEntry],
    *,
    stop_flag: StopFlag | None = None,
) -> list[AutostartEntry]:
    """
    For rows with a real file on disk:
      - compute SHA-256 if Autoruns left hashes empty
      - resolve blank signers via Authenticode (so MS Known DLLs aren't 'unsigned')
    """
    need_sig: list[Path] = []
    resolved: dict[int, Path] = {}

    for idx, e in enumerate(entries):
        if stop_flag and stop_flag():
            raise ScanCancelled("Cancelled.")
        path = _existing_path(e.image_path)
        if path is None:
            continue
        resolved[idx] = path
        # Prefer canonical path string for later display
        e.image_path = str(path)
        if not e.best_hash:
            try:
                e.sha256 = _sha256_file(path)
            except OSError:
                pass
        if not e.signer.strip():
            need_sig.append(path)

    # Unique paths for one PowerShell batch
    uniq: list[Path] = []
    seen: set[str] = set()
    for p in need_sig:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(p)

    sig_map = _authenticode_batch(uniq, stop_flag=stop_flag)
    for idx, path in resolved.items():
        e = entries[idx]
        if e.signer.strip():
            continue
        filled = sig_map.get(str(path).lower(), "")
        # Keep blank if still unsigned — that is a real unsigned file
        e.signer = filled

    return entries
