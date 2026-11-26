from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class AutostartEntry:
    time: str = ""
    entry_location: str = ""
    entry: str = ""
    enabled: str = ""
    category: str = ""
    profile: str = ""
    description: str = ""
    signer: str = ""
    company: str = ""
    image_path: str = ""
    version: str = ""
    launch_string: str = ""
    md5: str = ""
    sha1: str = ""
    pesha1: str = ""
    pesha256: str = ""
    sha256: str = ""
    imp: str = ""

    # Filled by VT enrichment (in memory only)
    vt_malicious: int | None = None
    vt_suspicious: int | None = None
    vt_undetected: int | None = None
    vt_total: int | None = None  # engines that returned a result
    vt_status: str = ""  # "", "ok", "not_found", "error", "skipped"
    vt_permalink: str = ""

    @property
    def best_hash(self) -> str:
        return (self.sha256 or self.pesha256 or self.sha1 or self.md5 or "").strip().lower()

    def is_microsoft_verified(self) -> bool:
        s = self.signer.lower()
        return s.startswith("(verified)") and "microsoft" in s

    def is_verified(self) -> bool:
        return self.signer.lower().startswith("(verified)")

    def is_not_verified(self) -> bool:
        return "(not verified)" in self.signer.lower()

    def is_unsigned(self) -> bool:
        signer = self.signer.strip()
        if not signer:
            return True
        return not self.is_verified() and not self.is_not_verified()

    def is_other_signed(self) -> bool:
        """Verified Authenticode, but not Microsoft."""
        return self.is_verified() and not self.is_microsoft_verified()

    def path_looks_suspicious(self) -> bool:
        from autorun_vt_audit.core.config import SUSPICIOUS_PATH_MARKERS

        p = (self.image_path or "").lower().replace("/", "\\")
        if not p or p.startswith("file not found"):
            return False
        return any(m in p for m in SUSPICIOUS_PATH_MARKERS)

    def interest_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.is_unsigned():
            reasons.append("unsigned")
        if self.is_not_verified():
            reasons.append("not_verified")
        if self.path_looks_suspicious():
            reasons.append("suspicious_path")
        path = (self.image_path or "").lower()
        if path.startswith("file not found"):
            reasons.append("missing_file")
        return reasons
