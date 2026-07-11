"""Local test for the detection-engineering skill's validate_rule.py.

Follows the same convention as the repo-root test_*.py files (test_* functions,
a main() driver, PASS:/AssertionError reporting) even though this test and the
script it exercises are synchronous and skill-local rather than async and tied
to the MCP server.

Run: python test_validate_rule.py
"""

import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))

from validate_rule import validate_rule, validate_rule_file  # noqa: E402

REFERENCE_DIR = SKILL_DIR / "reference"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_example_rule_is_valid():
    errors = validate_rule_file(REFERENCE_DIR / "example-rule.yml")
    assert errors == [], f"expected reference/example-rule.yml to be valid, got: {errors}"
    print("PASS: example_rule_is_valid")


def test_missing_fields_rule_fails_with_clear_reasons():
    errors = validate_rule_file(FIXTURES_DIR / "missing_fields.yml")
    assert errors, "expected missing_fields.yml to fail validation"
    assert any("'id'" in e for e in errors), errors
    assert any("'detection'" in e for e in errors), errors
    assert any("'level'" in e for e in errors), errors
    print("PASS: missing_fields_rule_fails_with_clear_reasons")


def test_malformed_yaml_fails_gracefully():
    errors = validate_rule_file(FIXTURES_DIR / "malformed.yml")
    assert errors, "expected malformed.yml to fail validation"
    assert any("YAML parse error" in e for e in errors), errors
    assert not any("Traceback" in e for e in errors), "raw traceback leaked into errors"
    print("PASS: malformed_yaml_fails_gracefully")


def test_missing_file_reports_not_found():
    errors = validate_rule_file(FIXTURES_DIR / "does-not-exist.yml")
    assert errors == [f"File not found: {FIXTURES_DIR / 'does-not-exist.yml'}"]
    print("PASS: missing_file_reports_not_found")


def test_condition_must_reference_a_defined_block():
    data = {
        "title": "Fixture - Dangling Condition",
        "id": "8f14e45f-ceea-4b8b-b6a3-000000000002",
        "status": "experimental",
        "description": "condition references a block that isn't defined",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 1}, "condition": "selection_typo"},
        "level": "low",
    }
    errors = validate_rule(data)
    assert any("does not reference" in e for e in errors), errors
    print("PASS: condition_must_reference_a_defined_block")


def test_unknown_level_is_flagged():
    data = {
        "title": "Fixture - Bad Level",
        "id": "8f14e45f-ceea-4b8b-b6a3-000000000003",
        "status": "experimental",
        "description": "level is not one of the recognized values",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 1}, "condition": "selection"},
        "level": "super-critical",
    }
    errors = validate_rule(data)
    assert any("not one of the recognized values" in e for e in errors), errors
    print("PASS: unknown_level_is_flagged")


def main():
    test_example_rule_is_valid()
    test_missing_fields_rule_fails_with_clear_reasons()
    test_malformed_yaml_fails_gracefully()
    test_missing_file_reports_not_found()
    test_condition_must_reference_a_defined_block()
    test_unknown_level_is_flagged()
    print("\nAll tests passed.")


if __name__ == "__main__":
    main()
