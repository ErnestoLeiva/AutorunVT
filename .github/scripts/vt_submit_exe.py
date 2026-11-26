#!/usr/bin/env python3
"""
Submit a file to VirusTotal (API v3) and print SHA-256 / GUI permalink.

Env:
  VT_API_KEY  — required for upload (if missing: hash-only, exit 0)

Usage:
  python vt_submit_exe.py path/to/AutorunVT.exe [--github-output]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

VT_API = "https://www.virustotal.com/api/v3"
# Free/public API accepts multipart uploads up to 32 MiB without a special URL.
_MAX_DIRECT_UPLOAD = 32 * 1024 * 1024
_UA = "AutorunVT-release/0.1"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _request(
    method: str,
    path: str,
    api_key: str,
    *,
    data: bytes | None = None,
    content_type: str | None = None,
    timeout: float = 120.0,
) -> tuple[int, dict | str]:
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": _UA,
    }
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(
        f"{VT_API}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            code = resp.getcode() or 200
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return exc.code, _maybe_json(raw)
    return code, _maybe_json(raw)


def _maybe_json(raw: str) -> dict | str:
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return raw


def _file_known(api_key: str, sha: str) -> bool:
    code, _body = _request("GET", f"/files/{sha}", api_key, timeout=30.0)
    return code == 200


def _multipart(field: str, filename: str, payload: bytes, boundary: str) -> bytes:
    CRLF = b"\r\n"
    parts = [
        f"--{boundary}".encode(),
        (
            f'Content-Disposition: form-data; name="{field}"; '
            f'filename="{filename}"'
        ).encode(),
        b"Content-Type: application/octet-stream",
        b"",
        payload,
        f"--{boundary}--".encode(),
        b"",
    ]
    return CRLF.join(parts)


def _upload(api_key: str, path: Path) -> str:
    """Return analysis id from VirusTotal."""
    size = path.stat().st_size
    upload_path = "/files"
    if size > _MAX_DIRECT_UPLOAD:
        code, body = _request("GET", "/files/upload_url", api_key, timeout=30.0)
        if code != 200 or not isinstance(body, dict):
            raise RuntimeError(f"upload_url failed ({code}): {body!r}")
        # Special upload uses absolute URL — handle separately below
        upload_url = body.get("data")
        if not isinstance(upload_url, str) or not upload_url:
            raise RuntimeError(f"upload_url missing data: {body!r}")
        return _upload_to_url(api_key, upload_url, path)

    boundary = f"----AutorunVT{int(time.time())}"
    data = _multipart("file", path.name, path.read_bytes(), boundary)
    code, body = _request(
        "POST",
        upload_path,
        api_key,
        data=data,
        content_type=f"multipart/form-data; boundary={boundary}",
        timeout=180.0,
    )
    if code not in (200, 201) or not isinstance(body, dict):
        raise RuntimeError(f"upload failed ({code}): {body!r}")
    analysis_id = (body.get("data") or {}).get("id")
    if not analysis_id:
        raise RuntimeError(f"upload response missing analysis id: {body!r}")
    return str(analysis_id)


def _upload_to_url(api_key: str, url: str, path: Path) -> str:
    boundary = f"----AutorunVT{int(time.time())}"
    data = _multipart("file", path.name, path.read_bytes(), boundary)
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": _UA,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300.0) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    analysis_id = (body.get("data") or {}).get("id")
    if not analysis_id:
        raise RuntimeError(f"large upload missing analysis id: {body!r}")
    return str(analysis_id)


def _wait_analysis(api_key: str, analysis_id: str, *, timeout_s: float = 90.0) -> str:
    """Poll until completed / timeout. Returns status string."""
    deadline = time.time() + timeout_s
    last = "unknown"
    while time.time() < deadline:
        code, body = _request(
            "GET", f"/analyses/{analysis_id}", api_key, timeout=30.0
        )
        if code == 200 and isinstance(body, dict):
            last = str(
                ((body.get("data") or {}).get("attributes") or {}).get("status")
                or "unknown"
            )
            if last == "completed":
                return last
        time.sleep(3.0)
    return last


def _emit(sha: str, *, status: str, github_output: bool) -> None:
    permalink = f"https://www.virustotal.com/gui/file/{sha}"
    print(f"sha256={sha}")
    print(f"permalink={permalink}")
    print(f"status={status}")
    if github_output:
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            with open(out, "a", encoding="utf-8") as fh:
                fh.write(f"sha256={sha}\n")
                fh.write(f"permalink={permalink}\n")
                fh.write(f"status={status}\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe", type=Path, help="Path to AutorunVT.exe")
    p.add_argument(
        "--github-output",
        action="store_true",
        help="Also append sha256/permalink/status to $GITHUB_OUTPUT",
    )
    p.add_argument(
        "--wait",
        type=float,
        default=90.0,
        help="Seconds to wait for analysis completion (0 = don't wait)",
    )
    args = p.parse_args(argv)

    exe: Path = args.exe
    if not exe.is_file():
        print(f"error: file not found: {exe}", file=sys.stderr)
        return 1

    sha = _sha256(exe)
    api_key = (os.environ.get("VT_API_KEY") or "").strip()
    if not api_key:
        print(
            "warning: VT_API_KEY not set — skipping VirusTotal upload "
            "(hash still emitted).",
            file=sys.stderr,
        )
        _emit(sha, status="skipped_no_key", github_output=args.github_output)
        return 0

    try:
        if _file_known(api_key, sha):
            print(f"VirusTotal already has this hash ({sha[:12]}…)", file=sys.stderr)
            _emit(sha, status="already_present", github_output=args.github_output)
            return 0

        print(f"Uploading {exe.name} ({exe.stat().st_size} bytes)…", file=sys.stderr)
        analysis_id = _upload(api_key, exe)
        status = "uploaded"
        if args.wait > 0:
            print(f"Waiting for analysis ({analysis_id})…", file=sys.stderr)
            polled = _wait_analysis(api_key, analysis_id, timeout_s=args.wait)
            status = f"uploaded_{polled}"
            print(f"Analysis status: {polled}", file=sys.stderr)
        _emit(sha, status=status, github_output=args.github_output)
    except Exception as exc:  # noqa: BLE001 — never fail the release over VT
        print(f"warning: VirusTotal submit failed: {exc}", file=sys.stderr)
        _emit(sha, status=f"error:{exc}", github_output=args.github_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
