#!/usr/bin/env python3
"""PostToolUse hook: run validate_rule.py's existing logic against any
newly written/edited Sigma/Hayabusa rule YAML.

Imports validate_rule_file() directly from
.claude/skills/detection-engineering/scripts/validate_rule.py (the same
sys.path pattern the skill's own tests/test_validate_rule.py already uses)
rather than re-implementing the schema check, so the two can never drift
apart.

The file has already been written by the time this hook runs, so a
validation failure cannot be undone here -- it is reported via
{"decision": "block", "reason": ...}, which feeds the reason back to
Claude as feedback to self-correct, not a real block of the completed
tool call.
"""

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import project_dir, read_hook_input  # noqa: E402

_SKILL_SCRIPTS_DIR = (
    Path(__file__).resolve().parent.parent / "skills" / "detection-engineering" / "scripts"
)
sys.path.insert(0, str(_SKILL_SCRIPTS_DIR))
from validate_rule import validate_rule_file  # noqa: E402


def should_skip(root: Path, resolved: Path) -> bool:
    try:
        rel = resolved.relative_to(root)
    except ValueError:
        return True  # outside the project; not ours to validate

    parts = rel.parts
    if parts and parts[0] == "hayabusa":
        return True  # bundled/gitignored, not hand-authored here
    if "fixtures" in parts:
        return True  # deliberately-invalid test fixtures
    return False


def looks_like_rule(path: Path) -> bool:
    """Heuristic: is this YAML file Sigma/Hayabusa-rule-shaped?

    Checks for "logsource" or "detection" rather than requiring both --
    a rule missing one of those (exactly the kind of thing validate_rule.py
    is meant to catch) must still be recognized as a rule, not silently
    skipped.
    """
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return False
    return isinstance(data, dict) and ("logsource" in data or "detection" in data)


def main() -> int:
    hook_input = read_hook_input()
    root = project_dir(hook_input)
    file_path = (hook_input.get("tool_input") or {}).get("file_path")

    if not file_path or not str(file_path).lower().endswith((".yml", ".yaml")):
        return 0

    raw = Path(file_path)
    resolved = raw if raw.is_absolute() else root / raw
    resolved = resolved.resolve()

    if not resolved.is_file() or should_skip(root, resolved):
        return 0

    if not looks_like_rule(resolved):
        return 0

    errors = validate_rule_file(resolved)
    if not errors:
        return 0

    reason = f"validate_rule.py flagged {resolved.name}:\n" + "\n".join(
        f"- {e}" for e in errors
    )
    print(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
