#!/usr/bin/env python3
"""Validate a draft Sigma/Hayabusa detection rule YAML file.

Checks the same fields hayabusa-mcp's server.py relies on when parsing rules
(list_rules(), _matches_for_technique()) so this can't drift from what the
server actually consumes. See ../reference/rule-schema.md for the field
reference this check is based on.

Usage: python validate_rule.py <path-to-rule.yml>
Exits 0 with "VALID" if the rule passes, 1 with a list of reasons if not.
"""

import re
import sys
import uuid
from pathlib import Path

import yaml

REQUIRED_FIELDS = ("title", "id", "status", "description", "logsource", "detection", "level")

KNOWN_LEVELS = {"informational", "low", "medium", "high", "critical"}


def validate_rule(data: object) -> list[str]:
    """Return a list of validation error strings; empty list means valid."""
    errors = []

    if not isinstance(data, dict):
        return ["Rule content is not a YAML mapping (top-level dict)."]

    for field in REQUIRED_FIELDS:
        if field not in data or data.get(field) in (None, ""):
            errors.append(f"Missing required field: '{field}'")

    if "id" in data and data.get("id") not in (None, ""):
        try:
            uuid.UUID(str(data["id"]))
        except (ValueError, AttributeError, TypeError):
            errors.append(f"Field 'id' is not a valid UUID: {data['id']!r}")

    if "logsource" in data and data.get("logsource") not in (None, ""):
        logsource = data["logsource"]
        if not isinstance(logsource, dict):
            errors.append("Field 'logsource' must be a mapping (e.g. {product: windows}).")
        elif not logsource.get("product"):
            errors.append("Field 'logsource' is missing 'product'.")

    if "detection" in data and data.get("detection") not in (None, ""):
        detection = data["detection"]
        if not isinstance(detection, dict):
            errors.append("Field 'detection' must be a mapping.")
        else:
            condition = detection.get("condition")
            if not condition or not isinstance(condition, str):
                errors.append("Field 'detection' is missing a string 'condition'.")
            selection_keys = [k for k in detection if k != "condition"]
            if not selection_keys:
                errors.append(
                    "Field 'detection' has a 'condition' but no selection/filter blocks "
                    "for it to reference."
                )
            elif condition and isinstance(condition, str):
                condition_words = set(re.findall(r"[\w-]+", condition))
                referenced = [k for k in selection_keys if k in condition_words]
                if not referenced:
                    errors.append(
                        f"Field 'detection.condition' ({condition!r}) does not reference "
                        f"any of the defined blocks: {selection_keys}"
                    )

    level = data.get("level")
    if level and isinstance(level, str) and level.lower() not in KNOWN_LEVELS:
        errors.append(
            f"Field 'level' ({level!r}) is not one of the recognized values: "
            f"{sorted(KNOWN_LEVELS)}"
        )

    tags = data.get("tags")
    if tags is not None and not isinstance(tags, list):
        errors.append("Field 'tags', if present, must be a list.")

    return errors


def validate_rule_file(path: Path) -> list[str]:
    if not path.is_file():
        return [f"File not found: {path}"]
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    return validate_rule(data)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python validate_rule.py <path-to-rule.yml>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    errors = validate_rule_file(path)

    if not errors:
        print(f"VALID: {path}")
        return 0

    print(f"INVALID: {path}")
    for error in errors:
        print(f"  - {error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
