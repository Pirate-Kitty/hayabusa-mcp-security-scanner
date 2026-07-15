#!/usr/bin/env python3
"""Shared helpers for this project's Claude Code hook scripts.

Kept tiny and dependency-free (stdlib only) since every hook script here
imports it directly via sys.path, not through package installation.
"""

import json
import os
import sys
from pathlib import Path


def read_hook_input() -> dict:
    """Read and parse the hook's stdin JSON payload.

    Returns {} on any parse failure so a caller can treat it as "no opinion"
    rather than crashing the hook.
    """
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def project_dir(hook_input: dict | None = None) -> Path:
    """Resolve the project root.

    Prefers $CLAUDE_PROJECT_DIR (set by Claude Code for hook subprocesses),
    falls back to the hook input's own "cwd" field, then os.getcwd().
    """
    env_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    if hook_input and hook_input.get("cwd"):
        return Path(hook_input["cwd"]).resolve()
    return Path.cwd().resolve()
