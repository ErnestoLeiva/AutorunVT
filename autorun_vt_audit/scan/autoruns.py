from __future__ import annotations

import csv
import io
from collections.abc import Callable
from pathlib import Path

from autorun_vt_audit.core.config import find_autorunsc
from autorun_vt_audit.core.models import AutostartEntry
from autorun_vt_audit.scan.enrich import finalize_entries
from autorun_vt_audit.win.proc import ScanCancelled, run_hidden_cancellable

ProgressCb = Callable[[str], None]
StopFlag = Callable[[], bool]

# autorunsc CSV header names (v14.x)
_FIELD_MAP = {
    "Time": "time",
    "Entry Location": "entry_location",
    "Entry": "entry",
    "Enabled": "enabled",
    "Category": "category",
    "Profile": "profile",
    "Description": "description",
    "Signer": "signer",
    "Company": "company",
    "Image Path": "image_path",
    "Version": "version",
    "Launch String": "launch_string",
    "MD5": "md5",
    "SHA-1": "sha1",
    "PESHA-1": "pesha1",
    "PESHA-256": "pesha256",
    "SHA-256": "sha256",
    "IMP": "imp",
}


def _parse_csv(text: str) -> list[AutostartEntry]:
    # Skip banner/blank lines until the header row
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = 0
    for i, ln in enumerate(lines[:8]):
        if "Entry Location" in ln or ln.startswith("Time,"):
            header_idx = i
            break
    blob = "\n".join(lines[header_idx:])
    reader = csv.DictReader(io.StringIO(blob))
    out: list[AutostartEntry] = []
    for row in reader:
        kwargs = {}
        for csv_key, attr in _FIELD_MAP.items():
            kwargs[attr] = (row.get(csv_key) or "").strip()
        entry = AutostartEntry(**kwargs)
        # Drop empty / category-only noise rows (Autoruns emits these stubs)
        if not any((entry.entry, entry.image_path, entry.entry_location)):
            continue
        if not entry.entry and not entry.image_path:
            continue
        out.append(entry)
    return out


def run_prescan(
    *,
    hide_microsoft: bool = False,
    all_users: bool = True,
    autorunsc: Path | None = None,
    on_progress: ProgressCb | None = None,
    stop_flag: StopFlag | None = None,
) -> list[AutostartEntry]:
    """
    Run autorunsc with -a * -c -h -s -t (and optional -m).
    CSV is parsed in memory — nothing written to disk.
    Raises ScanCancelled if stop_flag becomes true (kills autorunsc if still running).
    """
    exe = autorunsc or find_autorunsc()
    if exe is None:
        raise FileNotFoundError(
            "autorunsc64.exe not found. Install Sysinternals Autoruns or set AUTORUNSC_PATH."
        )

    cmd = [
        str(exe),
        "-accepteula",
        "-nobanner",
        "-a",
        "*",
        "-c",
        "-h",
        "-s",
        "-t",
    ]
    if hide_microsoft:
        cmd.append("-m")
    if all_users:
        cmd.append("*")

    if on_progress:
        flags = " ".join(cmd[1:])
        on_progress(f"Running: {exe.name} {flags}")

    if stop_flag and stop_flag():
        raise ScanCancelled("Cancelled.")

    # Hidden console — cancellable (kill child on Cancel)
    proc = run_hidden_cancellable(cmd, stop_flag=stop_flag)
    raw = proc.stdout
    if not raw and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"autorunsc failed (exit {proc.returncode}): {err}")

    if stop_flag and stop_flag():
        raise ScanCancelled("Cancelled.")

    text = None
    for enc in ("utf-16", "utf-16-le", "utf-8-sig", "utf-8", "cp1252"):
        try:
            text = raw.decode(enc)
            if "Entry Location" in text or "SHA-256" in text or "Signer" in text:
                break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = raw.decode("utf-8", errors="replace")

    entries = _parse_csv(text)
    if stop_flag and stop_flag():
        raise ScanCancelled("Cancelled.")
    if on_progress:
        on_progress(f"Parsed {len(entries)} autostart entries into memory.")
        on_progress("Filling missing hashes / Authenticode for incomplete rows…")
    finalize_entries(entries, stop_flag=stop_flag)
    if stop_flag and stop_flag():
        raise ScanCancelled("Cancelled.")
    if on_progress:
        on_progress("Local hash/signer enrichment complete.")

    # autorunsc -m can still leave rows that only look Microsoft after our
    # Authenticode fill (e.g. Known DLLs). Drop them so −m matches intent.
    if hide_microsoft:
        before = len(entries)
        entries = [e for e in entries if not e.is_microsoft_verified()]
        dropped = before - len(entries)
        if on_progress and dropped:
            on_progress(
                f"Excluded {dropped} Microsoft-signed entries after enrichment (−m)."
            )

    return entries


def summarize(entries: list[AutostartEntry]) -> dict[str, int]:
    unsigned = [e for e in entries if e.is_unsigned()]
    unsigned_scannable = [
        e
        for e in unsigned
        if e.best_hash and (e.image_path or "") and not (e.image_path or "").lower().startswith("file not found")
    ]
    return {
        "total": len(entries),
        "microsoft_verified": sum(1 for e in entries if e.is_microsoft_verified()),
        "other_verified": sum(
            1 for e in entries if e.is_verified() and not e.is_microsoft_verified()
        ),
        "not_verified": sum(1 for e in entries if e.is_not_verified()),
        "unsigned": len(unsigned),
        "unsigned_scannable": len(unsigned_scannable),
        "suspicious_path": sum(1 for e in entries if e.path_looks_suspicious()),
        "missing_file": sum(
            1 for e in entries if (e.image_path or "").lower().startswith("file not found")
        ),
    }


def is_vt_candidate(
    entry: AutostartEntry,
    *,
    unsigned: bool = True,
    not_verified: bool = True,
    suspicious_path: bool = True,
    other_signed: bool = False,
    ignore_microsoft: bool = True,
    skip_missing: bool = True,
) -> bool:
    """
    True only for rows VirusTotal can actually look up:
    real image path + hash + at least one include filter.
    """
    if ignore_microsoft and entry.is_microsoft_verified():
        return False

    path = (entry.image_path or "").strip()
    path_l = path.lower()
    if not path or path_l.startswith("file not found"):
        return False if skip_missing else bool(entry.best_hash)

    if not entry.best_hash:
        return False

    if not (entry.entry or path):
        return False

    # Category toggles are INCLUDES (narrow the set).
    # If every category toggle is OFF → show all scannable rows
    # (still respects ignore_microsoft). That way turning filters off
    # widens the list instead of emptying it.
    any_category = any((unsigned, not_verified, suspicious_path, other_signed))
    if not any_category:
        return True

    if unsigned and entry.is_unsigned():
        return True
    if not_verified and entry.is_not_verified():
        return True
    if suspicious_path and entry.path_looks_suspicious():
        return True
    if other_signed and entry.is_other_signed():
        return True
    return False


def filter_vt_candidates(
    entries: list[AutostartEntry],
    *,
    unsigned: bool = True,
    not_verified: bool = True,
    suspicious_path: bool = True,
    other_signed: bool = False,
    ignore_microsoft: bool = True,
    skip_missing: bool = True,
) -> list[AutostartEntry]:
    """All rows that would qualify as VT targets (duplicates kept for the table)."""
    return [
        e
        for e in entries
        if is_vt_candidate(
            e,
            unsigned=unsigned,
            not_verified=not_verified,
            suspicious_path=suspicious_path,
            other_signed=other_signed,
            ignore_microsoft=ignore_microsoft,
            skip_missing=skip_missing,
        )
    ]


def select_for_vt(
    entries: list[AutostartEntry],
    *,
    unsigned: bool = True,
    not_verified: bool = True,
    suspicious_path: bool = True,
    other_signed: bool = False,
    ignore_microsoft: bool = True,
    skip_missing: bool = True,
) -> list[AutostartEntry]:
    """Deduped-by-hash list of interesting entries for VT lookup."""
    chosen: list[AutostartEntry] = []
    seen: set[str] = set()
    for e in filter_vt_candidates(
        entries,
        unsigned=unsigned,
        not_verified=not_verified,
        suspicious_path=suspicious_path,
        other_signed=other_signed,
        ignore_microsoft=ignore_microsoft,
        skip_missing=skip_missing,
    ):
        h = e.best_hash
        if not h or h in seen:
            continue
        seen.add(h)
        chosen.append(e)
    return chosen
