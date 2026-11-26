#!/usr/bin/env python3
"""Reset config.ini.example to safe placeholders (CI safety net).

- [onepassword] enabled → false
- environment_id → empty
- api_key → empty
- secret_name → VT_API_KEY
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "config.ini.example"

# Values that count as "already a placeholder" (case-insensitive for ids/keys).
_EMPTY_PLACEHOLDERS = frozenset(
    {
        "",
        "your-environment-id",
        "your_environment_id",
        "<environment_id>",
        "changeme",
        "xxx",
        "todo",
    }
)
_API_KEY_PLACEHOLDERS = frozenset(
    {
        "",
        "your_vt_api_key",
        "your-vt-api-key",
        "<api_key>",
        "changeme",
        "xxx",
        "todo",
    }
)

_KEY_LINE = re.compile(
    r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*?)(\s*)$"
)


def _is_placeholder(value: str, allowed: frozenset[str]) -> bool:
    return value.strip().lower() in allowed


def scrub_text(text: str) -> str:
    out: list[str] = []
    section = ""
    for line in text.splitlines(keepends=True):
        raw = line.rstrip("\r\n")
        ending = line[len(raw) :]

        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            out.append(line)
            continue

        if stripped.startswith(";") or stripped.startswith("#") or not stripped:
            out.append(line)
            continue

        m = _KEY_LINE.match(raw)
        if not m:
            out.append(line)
            continue

        indent, key, eq, value, trail = m.groups()
        key_l = key.lower()

        if section == "onepassword" and key_l == "enabled":
            if value.strip().lower() != "false":
                out.append(f"{indent}{key}{eq}false{trail}{ending}")
            else:
                out.append(line)
            continue

        if key_l == "environment_id":
            if not _is_placeholder(value, _EMPTY_PLACEHOLDERS):
                out.append(f"{indent}{key}{eq}{trail}{ending}")
            else:
                # Normalize any synonym placeholder → blank
                if value.strip() != "":
                    out.append(f"{indent}{key}{eq}{trail}{ending}")
                else:
                    out.append(line)
            continue

        if key_l == "api_key":
            if not _is_placeholder(value, _API_KEY_PLACEHOLDERS):
                out.append(f"{indent}{key}{eq}{trail}{ending}")
            else:
                if value.strip() != "":
                    out.append(f"{indent}{key}{eq}{trail}{ending}")
                else:
                    out.append(line)
            continue

        if key_l == "secret_name":
            if value.strip() != "VT_API_KEY":
                out.append(f"{indent}{key}{eq}VT_API_KEY{trail}{ending}")
            else:
                out.append(line)
            continue

        out.append(line)

    return "".join(out)


def scrub_file(path: Path) -> bool:
    before = path.read_text(encoding="utf-8")
    after = scrub_text(before)
    if after == before:
        return False
    path.write_text(after, encoding="utf-8", newline="\n")
    return True


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    paths = [Path(a) for a in argv] if argv else [EXAMPLE]

    changed: list[str] = []
    for path in paths:
        if not path.is_file():
            print(f"skip (missing): {path}", file=sys.stderr)
            continue
        if scrub_file(path):
            try:
                changed.append(str(path.resolve().relative_to(ROOT)))
            except ValueError:
                changed.append(str(path))

    if not changed:
        print("No .ini scrub needed.")
        return 0

    print("Scrubbed:")
    for rel in changed:
        print(f"  - {rel.replace(chr(92), '/')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
