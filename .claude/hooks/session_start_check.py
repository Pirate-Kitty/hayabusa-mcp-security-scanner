#!/usr/bin/env python3
"""SessionStart hook: read-only prerequisite checks for hayabusa-mcp.

Reports (via hookSpecificOutput.additionalContext) whether the Hayabusa
binary is present and executable, pyyaml is importable, and hayabusa-mcp is
enabled in .claude/settings.json. SessionStart cannot block a session
regardless of exit code, so this always exits 0 — it is advisory only.

Catches, in particular, the Linux unpacked-extension chmod-0600 regression
already documented in HANDOFF.md (the installed binary loses its execute
bit on reinstall) before it surfaces as a confusing scan_evtx failure.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import project_dir, read_hook_input  # noqa: E402


def check_hayabusa_binary(root: Path) -> str:
    hayabusa_dir = root / "hayabusa"
    if not hayabusa_dir.is_dir():
        return "MISSING: hayabusa/ not found -- run ./download_hayabusa.sh"

    candidates = sorted(p for p in hayabusa_dir.glob("hayabusa-*") if p.is_file())
    if not candidates:
        return "MISSING: no hayabusa-* binary found under hayabusa/"

    binary = candidates[0]
    if not os.access(binary, os.X_OK):
        return (
            f"NOT EXECUTABLE: {binary.name} lacks the execute bit -- a known "
            f"Linux unpacked-extension install regression (see HANDOFF.md); "
            f"fix with: chmod 755 {binary}"
        )
    return f"OK: {binary.name} present and executable"


def check_pyyaml() -> str:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return "MISSING: pyyaml not importable -- pip install -r requirements.txt"
    return "OK: pyyaml importable"


def check_mcp_enabled(root: Path) -> str:
    mcp_json_path = root / ".mcp.json"
    settings_path = root / ".claude" / "settings.json"

    if not mcp_json_path.is_file():
        return "MISSING: .mcp.json not found"
    if not settings_path.is_file():
        return "MISSING: .claude/settings.json not found"

    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return "UNKNOWN: .claude/settings.json unreadable or invalid JSON"

    enabled = settings.get("enabledMcpjsonServers", [])
    if "hayabusa-mcp" not in enabled:
        return "MISSING: 'hayabusa-mcp' not in enabledMcpjsonServers"
    return "OK: hayabusa-mcp enabled"


def build_summary(root: Path) -> str:
    lines = [
        check_hayabusa_binary(root),
        check_pyyaml(),
        check_mcp_enabled(root),
    ]
    return "hayabusa-mcp prerequisite check:\n" + "\n".join(f"- {line}" for line in lines)


def main() -> int:
    hook_input = read_hook_input()
    root = project_dir(hook_input)

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": build_summary(root),
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
