from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from autorun_vt_audit.core.config import (
    VT_API_KEY_ENV,
    VT_MAX_PER_DAY,
    VT_MAX_PER_MINUTE,
    VT_MAX_PER_MONTH,
    VT_PARALLEL,
)
from autorun_vt_audit.core.models import AutostartEntry

ProgressCb = Callable[[str], None]


@dataclass
class VtQuotaSnapshot:
    """Live numbers from GET /users/{apikey}/overall_quotas (free — no quota use)."""

    daily_used: int = 0
    daily_allowed: int = VT_MAX_PER_DAY
    monthly_used: int = 0
    monthly_allowed: int = VT_MAX_PER_MONTH
    ok: bool = False
    error: str = ""

    @property
    def daily_remaining(self) -> int:
        return max(0, self.daily_allowed - self.daily_used)

    @property
    def monthly_remaining(self) -> int:
        return max(0, self.monthly_allowed - self.monthly_used)

    @property
    def remaining(self) -> int:
        return min(self.daily_remaining, self.monthly_remaining)

    def status_line(self) -> str:
        if not self.ok:
            return f"VT quota: unavailable ({self.error or 'no key / fetch failed'})"
        return (
            f"VT day {self.daily_used}/{self.daily_allowed} "
            f"({self.daily_remaining} left) · "
            f"month {self.monthly_used}/{self.monthly_allowed} "
            f"({self.monthly_remaining} left)"
        )


def require_api_key() -> str:
    key = (os.environ.get(VT_API_KEY_ENV) or "").strip()
    if not key:
        raise RuntimeError(
            f"{VT_API_KEY_ENV} is not set. Start via AutorunVT.pyw "
            f"so 1Password injects the key."
        )
    return key


def _vt_get_json(path: str, api_key: str, *, timeout: float = 30.0) -> dict:
    url = f"https://www.virustotal.com/api/v3{path}"
    req = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "AutorunVT/0.1",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_overall_quotas(api_key: str | None = None) -> VtQuotaSnapshot:
    """
    VirusTotal source of truth for daily + monthly API request caps.
    Docs: does not consume quota.
    """
    snap = VtQuotaSnapshot()
    try:
        key = api_key or require_api_key()
    except RuntimeError as exc:
        snap.error = str(exc)
        return snap

    try:
        # Path id is the API key for self-lookup
        key_path = urllib.parse.quote(key, safe="")
        payload = _vt_get_json(f"/users/{key_path}/overall_quotas", key)
        data = payload.get("data") or {}

        def _user_bucket(name: str) -> tuple[int, int]:
            block = (data.get(name) or {}).get("user") or {}
            allowed = int(block.get("allowed") or 0)
            used = int(block.get("used") or 0)
            return used, allowed

        d_used, d_allowed = _user_bucket("api_requests_daily")
        m_used, m_allowed = _user_bucket("api_requests_monthly")
        snap.daily_used = d_used
        snap.daily_allowed = d_allowed or VT_MAX_PER_DAY
        snap.monthly_used = m_used
        snap.monthly_allowed = m_allowed or VT_MAX_PER_MONTH
        snap.ok = True
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        snap.error = f"HTTP {exc.code}: {body[:160]}"
    except Exception as exc:  # noqa: BLE001
        snap.error = str(exc)
    return snap


@dataclass
class RateLimiter:
    """4 parallel / minute; day + month remaining from VirusTotal overall_quotas."""

    max_per_minute: int = VT_MAX_PER_MINUTE
    parallel: int = VT_PARALLEL
    _minute_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _window_start: float = field(default=0.0, init=False)
    _window_count: int = field(default=0, init=False)
    _snap: VtQuotaSnapshot = field(default_factory=VtQuotaSnapshot, init=False)
    _snap_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def refresh_quotas(
        self,
        api_key: str | None = None,
        on_progress: ProgressCb | None = None,
    ) -> VtQuotaSnapshot:
        snap = fetch_overall_quotas(api_key)
        with self._snap_lock:
            self._snap = snap
        if on_progress:
            on_progress(snap.status_line())
        return snap

    @property
    def snapshot(self) -> VtQuotaSnapshot:
        with self._snap_lock:
            return self._snap

    @property
    def remaining_today(self) -> int:
        return self.snapshot.daily_remaining

    @property
    def remaining_month(self) -> int:
        return self.snapshot.monthly_remaining

    @property
    def remaining(self) -> int:
        return self.snapshot.remaining

    def wait_for_parallel_slots(
        self,
        wanted: int,
        api_key: str,
        on_progress: ProgressCb | None = None,
    ) -> int:
        """
        Refresh VT quotas, then grant min(wanted, parallel, day left, month left).
        Returns 0 if either budget is exhausted.
        """
        snap = self.refresh_quotas(api_key, on_progress=None)
        if not snap.ok:
            if on_progress:
                on_progress(f"Could not read VT quotas: {snap.error}")
            # Fail closed — don't burn requests if we can't see budget
            return 0

        left = snap.remaining
        if left <= 0:
            if on_progress:
                if snap.daily_remaining <= 0:
                    on_progress(
                        f"Daily VT budget exhausted "
                        f"({snap.daily_used}/{snap.daily_allowed})."
                    )
                else:
                    on_progress(
                        f"Monthly VT budget exhausted "
                        f"({snap.monthly_used}/{snap.monthly_allowed})."
                    )
            return 0

        granted = min(wanted, self.parallel, self.max_per_minute, left)

        with self._minute_lock:
            now = time.monotonic()
            if self._window_start == 0.0 or (now - self._window_start) >= 60.0:
                self._window_start = now
                self._window_count = 0
            need_wait = self._window_count + granted > self.max_per_minute
            sleep_for = max(0.0, 60.0 - (now - self._window_start)) if need_wait else 0.0

        if sleep_for > 0:
            if on_progress:
                on_progress(
                    f"Rate limit: waiting {sleep_for:.1f}s "
                    f"(next burst of {granted}, ≤{self.max_per_minute}/min)…"
                )
            time.sleep(sleep_for)
            with self._minute_lock:
                self._window_start = time.monotonic()
                self._window_count = 0

        with self._minute_lock:
            now = time.monotonic()
            if now - self._window_start >= 60.0:
                self._window_start = now
                self._window_count = 0
            self._window_count += granted

        return granted


def lookup_file(
    file_hash: str,
    api_key: str,
    *,
    timeout: float = 30.0,
) -> dict:
    try:
        return _vt_get_json(f"/files/{file_hash}", api_key, timeout=timeout)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            return {"_status": "not_found", "_body": body}
        if exc.code == 429:
            return {"_status": "rate_limited", "_body": body}
        return {"_status": "error", "_code": exc.code, "_body": body}


def _apply_result(entry: AutostartEntry, result: dict) -> None:
    status = result.get("_status")
    h = entry.best_hash
    if status == "not_found":
        entry.vt_status = "not_found"
        return
    if status == "rate_limited":
        entry.vt_status = "error"
        return
    if status == "error":
        entry.vt_status = "error"
        return
    attrs = (result.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    entry.vt_malicious = int(stats.get("malicious") or 0)
    entry.vt_suspicious = int(stats.get("suspicious") or 0)
    entry.vt_undetected = int(stats.get("undetected") or 0)
    # Classic VT UI is detections/engines (e.g. 0/72), not malicious/suspicious
    entry.vt_total = sum(int(v or 0) for v in stats.values())
    entry.vt_status = "ok"
    entry.vt_permalink = f"https://www.virustotal.com/gui/file/{h}"


def enrich_entries(
    entries: list[AutostartEntry],
    *,
    limiter: RateLimiter | None = None,
    on_progress: ProgressCb | None = None,
    stop_flag: Callable[[], bool] | None = None,
) -> list[AutostartEntry]:
    """
    Hash-only lookups (no uploads). Up to VT_PARALLEL in parallel, then 60s cool-down.
    Day/month caps come from VirusTotal overall_quotas (not a local file).
    """
    api_key = require_api_key()
    limiter = limiter or RateLimiter()
    total = len(entries)
    done = 0
    i = 0

    snap = limiter.refresh_quotas(api_key, on_progress)
    if not snap.ok:
        raise RuntimeError(f"VirusTotal quota check failed: {snap.error}")

    while i < total:
        if stop_flag and stop_flag():
            if on_progress:
                on_progress("VirusTotal enrichment cancelled.")
            break

        batch: list[AutostartEntry] = []
        while i < total and len(batch) < limiter.parallel:
            e = entries[i]
            i += 1
            if not e.best_hash:
                e.vt_status = "skipped"
                done += 1
                continue
            batch.append(e)

        if not batch:
            continue

        granted = limiter.wait_for_parallel_slots(len(batch), api_key, on_progress)
        if granted == 0:
            for e in batch:
                e.vt_status = "skipped"
            for e in entries[i:]:
                if not e.vt_status:
                    e.vt_status = "skipped"
            break

        if granted < len(batch):
            overflow = batch[granted:]
            batch = batch[:granted]
            i -= len(overflow)

        snap = limiter.snapshot
        labels = ", ".join((e.entry or e.image_path or "?")[:28] for e in batch)
        if on_progress:
            on_progress(
                f"VT burst [{done + 1}–{done + len(batch)}/{total}] "
                f"×{len(batch)} parallel — day {snap.daily_remaining} left, "
                f"month {snap.monthly_remaining} left · {labels}"
            )

        def _one(entry: AutostartEntry) -> tuple[AutostartEntry, dict]:
            result = lookup_file(entry.best_hash, api_key)
            if result.get("_status") == "rate_limited":
                time.sleep(60)
                result = lookup_file(entry.best_hash, api_key)
            return entry, result

        with ThreadPoolExecutor(max_workers=len(batch)) as pool:
            futures = [pool.submit(_one, e) for e in batch]
            for fut in as_completed(futures):
                entry, result = fut.result()
                _apply_result(entry, result)
                if result.get("_status") == "error" and on_progress:
                    on_progress(
                        f"VT error HTTP {result.get('_code')}: "
                        f"{str(result.get('_body', ''))[:120]}"
                    )
                done += 1

        if i < total and not (stop_flag and stop_flag()):
            if on_progress:
                on_progress(
                    f"Cooling down 60s before next parallel burst "
                    f"(≤{limiter.max_per_minute}/min)…"
                )
            end = time.monotonic() + 60.0
            while time.monotonic() < end:
                if stop_flag and stop_flag():
                    break
                time.sleep(0.25)
            with limiter._minute_lock:
                limiter._window_start = time.monotonic()
                limiter._window_count = 0

    limiter.refresh_quotas(api_key, on_progress)
    return entries
