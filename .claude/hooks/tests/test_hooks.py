"""Local tests for this project's Claude Code hook scripts.

Follows the same convention as the repo-root test_*.py files and the
detection-engineering skill's own tests/test_validate_rule.py: plain
functions imported directly (no pytest), PASS:/AssertionError reporting,
a main() driver.

Run: python .claude/hooks/tests/test_hooks.py
"""

import sys
import tempfile
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = HOOKS_DIR.parent.parent
sys.path.insert(0, str(HOOKS_DIR))

from protect_sensitive_paths import classify  # noqa: E402
from validate_rule_hook import looks_like_rule, should_skip  # noqa: E402
from session_start_check import (  # noqa: E402
    check_hayabusa_binary,
    check_mcp_enabled,
    check_pyyaml,
)

EXAMPLE_RULE = (
    REPO_ROOT / ".claude" / "skills" / "detection-engineering" / "reference" / "example-rule.yml"
)
MISSING_FIELDS_FIXTURE = (
    REPO_ROOT / ".claude" / "skills" / "detection-engineering" / "tests" / "fixtures"
    / "missing_fields.yml"
)


def test_protect_sensitive_paths_denies_git():
    reason = classify(REPO_ROOT, ".git/config")
    assert reason is not None and "protected" in reason, reason
    print("PASS: protect_sensitive_paths_denies_git")


def test_protect_sensitive_paths_denies_settings():
    for candidate in (".claude/settings.json", ".claude/settings.local.json"):
        reason = classify(REPO_ROOT, candidate)
        assert reason is not None and "settings" in reason, (candidate, reason)
    print("PASS: protect_sensitive_paths_denies_settings")


def test_protect_sensitive_paths_denies_hayabusa_dir():
    reason = classify(REPO_ROOT, "hayabusa/hayabusa-3.10.0-lin-x64-gnu")
    assert reason is not None and "hayabusa" in reason, reason
    print("PASS: protect_sensitive_paths_denies_hayabusa_dir")


def test_protect_sensitive_paths_denies_lib_dir():
    reason = classify(REPO_ROOT, "lib/foo.py")
    assert reason is not None and "lib" in reason, reason
    print("PASS: protect_sensitive_paths_denies_lib_dir")


def test_protect_sensitive_paths_denies_traversal():
    reason = classify(REPO_ROOT, "../outside-repo/file")
    assert reason == "path resolves outside the project root", reason
    print("PASS: protect_sensitive_paths_denies_traversal")


def test_protect_sensitive_paths_traversal_message_leaks_no_path_or_username():
    reason = classify(REPO_ROOT, "../outside-repo/file")
    assert str(REPO_ROOT) not in reason, reason
    assert "/" not in reason, reason  # nothing path-shaped leaked at all
    print("PASS: protect_sensitive_paths_traversal_message_leaks_no_path_or_username")


def test_protect_sensitive_paths_denies_absolute_path_outside_root():
    reason = classify(REPO_ROOT, "/etc/passwd")
    assert reason == "path resolves outside the project root", reason
    assert "/etc/passwd" not in reason, reason
    print("PASS: protect_sensitive_paths_denies_absolute_path_outside_root")


def test_protect_sensitive_paths_denies_absolute_in_repo_sensitive_path():
    absolute_settings_path = str(REPO_ROOT / ".claude" / "settings.json")
    reason = classify(REPO_ROOT, absolute_settings_path)
    assert reason is not None and "settings" in reason, reason
    print("PASS: protect_sensitive_paths_denies_absolute_in_repo_sensitive_path")


def test_protect_sensitive_paths_denies_mixed_case_git():
    reason = classify(REPO_ROOT, ".GIT/config")
    assert reason is not None and "protected" in reason, reason
    print("PASS: protect_sensitive_paths_denies_mixed_case_git")


def test_protect_sensitive_paths_denies_mixed_case_settings():
    reason = classify(REPO_ROOT, ".Claude/Settings.JSON")
    assert reason is not None and "settings" in reason, reason
    print("PASS: protect_sensitive_paths_denies_mixed_case_settings")


def test_protect_sensitive_paths_denies_mixed_case_hayabusa():
    reason = classify(REPO_ROOT, "HAYABUSA/x")
    assert reason is not None and "protected" in reason, reason
    print("PASS: protect_sensitive_paths_denies_mixed_case_hayabusa")


def test_protect_sensitive_paths_denies_dotenv():
    reason = classify(REPO_ROOT, ".env")
    assert reason is not None and "credential" in reason, reason
    print("PASS: protect_sensitive_paths_denies_dotenv")


def test_protect_sensitive_paths_denies_dotenv_variant():
    reason = classify(REPO_ROOT, ".env.production")
    assert reason is not None and "credential" in reason, reason
    print("PASS: protect_sensitive_paths_denies_dotenv_variant")


def test_protect_sensitive_paths_allows_dotenv_template():
    for name in (".env.example", ".env.sample", ".env.template"):
        reason = classify(REPO_ROOT, name)
        assert reason is None, (name, reason)
    print("PASS: protect_sensitive_paths_allows_dotenv_template")


def test_protect_sensitive_paths_denies_ssh_private_key_name():
    for name in ("some_dir/id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
        reason = classify(REPO_ROOT, name)
        assert reason is not None and "credential" in reason, (name, reason)
    print("PASS: protect_sensitive_paths_denies_ssh_private_key_name")


def test_protect_sensitive_paths_denies_key_and_cert_extensions():
    for name in (
        "certs/server.pem",
        "keys/private.key",
        "certs/bundle.pfx",
        "certs/bundle.p12",
        "certs/server.crt",
        "certs/server.cer",
    ):
        reason = classify(REPO_ROOT, name)
        assert reason is not None and "credential" in reason, (name, reason)
    print("PASS: protect_sensitive_paths_denies_key_and_cert_extensions")


def test_protect_sensitive_paths_denies_credentials_names():
    for name in ("config/credentials.json", "config/credentials", ".npmrc", ".netrc"):
        reason = classify(REPO_ROOT, name)
        assert reason is not None and "credential" in reason, (name, reason)
    print("PASS: protect_sensitive_paths_denies_credentials_names")


def test_protect_sensitive_paths_denies_credential_dirs():
    # .ssh/authorized_keys and .gnupg/secring.gpg isolate the directory-prefix
    # rule cleanly (neither basename matches any name/extension rule on its
    # own). .aws/credentials is left in for readability even though bare
    # "credentials" is independently name-matched too.
    for name, keyword in ((".ssh/authorized_keys", "credential"), (".aws/credentials", "credential"), (".gnupg/secring.gpg", "credential")):
        reason = classify(REPO_ROOT, name)
        assert reason is not None and keyword in reason, (name, reason)
    print("PASS: protect_sensitive_paths_denies_credential_dirs")


def test_protect_sensitive_paths_denies_nested_credential_dirs():
    # Regression guard: directory rules must match at any depth, not just
    # the top-level path component.
    for name in (
        "some/nested/.ssh/authorized_keys",
        "vendor/nested/.aws/config",
        "build/subdir/.gnupg/secring.gpg",
    ):
        reason = classify(REPO_ROOT, name)
        assert reason is not None and "credential" in reason, (name, reason)
    print("PASS: protect_sensitive_paths_denies_nested_credential_dirs")


def test_protect_sensitive_paths_denies_nested_repo_internal_dirs():
    # Same regression guard for the original repo-internal directory rules
    # (.git/hayabusa/lib), which had the identical top-level-only bug.
    for name in (
        "some/nested/hayabusa/rules/x.yml",
        "deep/deep/deep/.git/hooks/pre-commit",
        "modules/lib/vendor.py",
    ):
        reason = classify(REPO_ROOT, name)
        assert reason is not None and "protected" in reason, (name, reason)
    print("PASS: protect_sensitive_paths_denies_nested_repo_internal_dirs")


def test_protect_sensitive_paths_symlink_resolves_into_sensitive_dir():
    with tempfile.TemporaryDirectory() as tmp:
        fake_root = Path(tmp).resolve()
        sensitive_dir = fake_root / "hayabusa"
        sensitive_dir.mkdir()
        (sensitive_dir / "rules.yml").write_text("title: x\n")
        link = fake_root / "innocuous_link"
        link.symlink_to(sensitive_dir)
        reason = classify(fake_root, "innocuous_link/rules.yml")
        assert reason is not None and "hayabusa" in reason, reason
    print("PASS: protect_sensitive_paths_symlink_resolves_into_sensitive_dir")


def test_protect_sensitive_paths_allows_ordinary_file():
    reason = classify(REPO_ROOT, "techniques/T1003.md")
    assert reason is None, reason
    print("PASS: protect_sensitive_paths_allows_ordinary_file")


def test_protect_sensitive_paths_allows_ordinary_source_and_test_files():
    # Guard against overbroad matching blocking normal project files.
    for name in (
        "server.py",
        "test_scan_evtx.py",
        "README.md",
        ".claude/skills/detection-engineering/reference/example-rule.yml",
        "docs/api-key-rotation.md",
    ):
        reason = classify(REPO_ROOT, name)
        assert reason is None, (name, reason)
    print("PASS: protect_sensitive_paths_allows_ordinary_source_and_test_files")


def test_validate_rule_hook_skips_hayabusa_dir():
    assert should_skip(REPO_ROOT, REPO_ROOT / "hayabusa" / "rules" / "hayabusa" / "x.yml")
    print("PASS: validate_rule_hook_skips_hayabusa_dir")


def test_validate_rule_hook_skips_fixtures():
    assert should_skip(REPO_ROOT, MISSING_FIELDS_FIXTURE)
    print("PASS: validate_rule_hook_skips_fixtures")


def test_validate_rule_hook_does_not_skip_ordinary_rule_path():
    ordinary = REPO_ROOT / "some_dir" / "rule.yml"
    assert not should_skip(REPO_ROOT, ordinary)
    print("PASS: validate_rule_hook_does_not_skip_ordinary_rule_path")


def test_looks_like_rule_true_for_example_rule():
    assert looks_like_rule(EXAMPLE_RULE)
    print("PASS: looks_like_rule_true_for_example_rule")


def test_looks_like_rule_false_for_non_rule_yaml():
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write("foo: bar\n")
        temp_path = Path(f.name)
    try:
        assert not looks_like_rule(temp_path)
    finally:
        temp_path.unlink()
    print("PASS: looks_like_rule_false_for_non_rule_yaml")


def test_looks_like_rule_true_for_rule_missing_detection_key():
    # A rule missing "detection" (exactly what validate_rule.py should flag)
    # must still be recognized as rule-shaped via its "logsource" key, not
    # silently skipped as "not a rule".
    assert looks_like_rule(MISSING_FIELDS_FIXTURE)
    print("PASS: looks_like_rule_true_for_rule_missing_detection_key")


def test_session_start_check_pyyaml_ok():
    assert check_pyyaml() == "OK: pyyaml importable"
    print("PASS: session_start_check_pyyaml_ok")


def test_session_start_check_hayabusa_binary():
    result = check_hayabusa_binary(REPO_ROOT)
    assert result.startswith(("OK:", "MISSING:", "NOT EXECUTABLE:")), result
    print("PASS: session_start_check_hayabusa_binary")


def test_session_start_check_mcp_enabled():
    assert check_mcp_enabled(REPO_ROOT) == "OK: hayabusa-mcp enabled"
    print("PASS: session_start_check_mcp_enabled")


def main():
    test_protect_sensitive_paths_denies_git()
    test_protect_sensitive_paths_denies_settings()
    test_protect_sensitive_paths_denies_hayabusa_dir()
    test_protect_sensitive_paths_denies_lib_dir()
    test_protect_sensitive_paths_denies_traversal()
    test_protect_sensitive_paths_traversal_message_leaks_no_path_or_username()
    test_protect_sensitive_paths_denies_absolute_path_outside_root()
    test_protect_sensitive_paths_denies_absolute_in_repo_sensitive_path()
    test_protect_sensitive_paths_denies_mixed_case_git()
    test_protect_sensitive_paths_denies_mixed_case_settings()
    test_protect_sensitive_paths_denies_mixed_case_hayabusa()
    test_protect_sensitive_paths_denies_dotenv()
    test_protect_sensitive_paths_denies_dotenv_variant()
    test_protect_sensitive_paths_allows_dotenv_template()
    test_protect_sensitive_paths_denies_ssh_private_key_name()
    test_protect_sensitive_paths_denies_key_and_cert_extensions()
    test_protect_sensitive_paths_denies_credentials_names()
    test_protect_sensitive_paths_denies_credential_dirs()
    test_protect_sensitive_paths_denies_nested_credential_dirs()
    test_protect_sensitive_paths_denies_nested_repo_internal_dirs()
    test_protect_sensitive_paths_symlink_resolves_into_sensitive_dir()
    test_protect_sensitive_paths_allows_ordinary_file()
    test_protect_sensitive_paths_allows_ordinary_source_and_test_files()
    test_validate_rule_hook_skips_hayabusa_dir()
    test_validate_rule_hook_skips_fixtures()
    test_validate_rule_hook_does_not_skip_ordinary_rule_path()
    test_looks_like_rule_true_for_example_rule()
    test_looks_like_rule_false_for_non_rule_yaml()
    test_looks_like_rule_true_for_rule_missing_detection_key()
    test_session_start_check_pyyaml_ok()
    test_session_start_check_hayabusa_binary()
    test_session_start_check_mcp_enabled()
    print("\nAll tests passed.")


if __name__ == "__main__":
    main()
