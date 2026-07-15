# Handoff: hayabusa-mcp

## Current project state

The MCP server (`hayabusa-mcp`) is implemented, connected via `.mcp.json`, and confirmed working end-to-end through Claude Code — both `scan_evtx` and `get_hayabusa_rules` have been invoked live (via `mcp__hayabusa-mcp__scan_evtx` and `mcp__hayabusa-mcp__get_hayabusa_rules`) and return real Hayabusa results.

Hayabusa itself was downloaded, checksum-verified, and tested successfully (see version/checksum section below).

A severity-filtering bug in `scan_evtx` has been fixed: `run_scan()` in `server.py` launches the Hayabusa subprocess with `cwd` set to `hayabusa/`, but was passing `evtx_path` through unresolved. A relative path would be existence-checked against the caller's cwd, then handed to Hayabusa, which resolved it relative to `hayabusa/` instead — silently missing the file (Hayabusa still exits 0), producing empty findings at every severity level. Fixed by resolving `evtx_path` to an absolute path (`Path(evtx_path).resolve()`) before use. Regression-tested in `test_scan_evtx.py` (both absolute- and relative-path invocations, asserting the sample's low-severity finding appears at `informational`/`low` and is absent at `medium`/`high`/`critical`).

`scan_evtx` also gained three new optional parameters:
- `rule_filter` — case-insensitive substring match against `RuleTitle`; non-matching findings are dropped.
- `output_format` — `"full"` (default, all fields) or `"summary"` (only `Timestamp, RuleTitle, Level, Computer, Channel, EventID, RecordID, RuleID`).
- `max_results` — caps the number of findings returned (applied after filtering).

All three default to prior behavior, so existing callers are unaffected.

A second tool, `get_hayabusa_rules`, has been added. It lists Hayabusa's bundled detection rules (parsed from the `.yml` files under `hayabusa/rules/hayabusa/` and `hayabusa/rules/sigma/`) and optionally filters them with a case-insensitive `keyword` match against a rule's title, description, or tags. Each returned rule includes `id`, `title`, `description`, `level`, `status`, `author`, `tags`, `logsource_product`, and `path` (relative to `hayabusa/rules/`). Rule YAML is parsed with `yaml.CSafeLoader` (libyaml) rather than the pure-Python loader — parsing all ~4,960 rule files takes ~1.5s with the C loader vs. ~17s without it, which matters since every call re-scans the rules directory. This required adding `pyyaml` as a dependency (`requirements.txt`, `.venv`).

**Important operational note:** after any change to `server.py`, the live MCP connection may be serving a stale subprocess. A `/mcp` reconnect is sometimes enough to pick up changes, but in some cases a full Claude Code restart is required to spawn a fresh server subprocess with the new code. This applies to the newly added `get_hayabusa_rules` tool too — reconnect before trying to call it live. Confirmed in practice: after adding `get_hayabusa_rules` to `server.py`, the tool was absent from the live tool list until a `/mcp` reconnect ("Reconnected to hayabusa-mcp.") picked up the change, after which the tool was callable.

`get_hayabusa_rules` was then exercised live through Claude Code with two queries:
- `keyword="credential_access"` (no match, wrong tag spelling) then `keyword="credential"` and `keyword="attack.credential-access"` (the actual tag format used in the rule files) — the latter matched roughly **300 rules**, large enough that the raw JSON response exceeded the MCP tool-output size limit and had to be summarized from the saved output file rather than read directly. This is a known limitation: unlike `scan_evtx`, `get_hayabusa_rules` has no `max_results`/pagination, so broad keyword queries against the ~4,960-rule set can overflow the output limit.
- `keyword="mimikatz"` — a narrower query that matched **28 rules** and returned successfully within the output limit, including rules like "HackTool - Mimikatz Execution", "Mimikatz DC Sync", "Mimikatz Use", and "Potential Invoke-Mimikatz PowerShell Script".

## Claude Desktop extension setup

The project was packaged as an unpacked Claude Desktop extension (MCPB manifest pattern):

- Added `manifest.json` at the project root (`dxt_version`, `name`, `version`, `description`, `author`, and a `server` block with `type: "python"`, `entry_point: "server.py"`).
- **ENOENT fix:** the first version of `manifest.json` pointed `mcp_config.command` at `${__dirname}/.venv/bin/python` — this failed with `ENOENT` because that `.venv` is external to the extension and won't exist wherever the extension is actually loaded from. Fixed by switching `command` to the system `python3` and adding `"env": {"PYTHONPATH": "${__dirname}/lib"}`, so the extension no longer depends on this project's `.venv` at all.
- Vendored `mcp`, `pyyaml`, and their transitive dependencies into a `lib/` directory inside the extension (`pip install --target=lib -r requirements.txt`), so dependencies ship with the extension rather than relying on any external Python environment.
- Verified standalone: both `test_get_hayabusa_rules.py` and `test_scan_evtx.py` pass when run with `/usr/bin/python3` (not the project `.venv`) and `PYTHONPATH=./lib`, confirming the vendored deps are sufficient on their own.
- Note: `lib/` contains platform-specific compiled wheels (e.g. `pydantic_core`, `cryptography`, `rpds_py`), so this vendored copy is tied to this machine's OS/architecture/Python version — not yet portable to a different platform if packaged and distributed elsewhere.
- After configuring the connection through this Claude Code instance, `get_hayabusa_rules` was exercised live from a **Claude Desktop** session (not Claude Code) with `keyword="mimikatz"`, which returned **26 matches** — confirming the extension runs and serves real Hayabusa rule data end-to-end from Claude Desktop. (This is a separate run from the 28-match Mimikatz test documented above, which was against the live Claude Code MCP connection.)
- `scan_evtx` was subsequently exercised live from Claude Desktop as well (absolute EVTX path), returning real findings — both tools are now confirmed working end-to-end through the Claude Desktop extension, not just Claude Code.
- **Linux unpacked-extension permission issue:** the installed extension copy of the Hayabusa binary (`~/.config/Claude/Claude Extensions/local.unpacked.pirate-kitty.hayabusa-mcp/hayabusa/hayabusa-3.10.0-lin-x64-gnu`) was copied in with mode `0600` (`-rw-------`, no execute bit) by the unpacked-extension install process, while the project's own copy was `0755`. This made `scan_evtx` fail with "Permission denied" from Claude Desktop even though the binary path resolved correctly and the file existed. Confirmed not a `noexec`-mount issue — both the project directory and the installed-extension directory sit on the same `ext4` root filesystem mounted `rw,relatime` with no `noexec`. The permission regressed again after reinstalling the unpacked extension, confirming the install process itself doesn't preserve/set the execute bit.
  - **Workaround applied:** `chmod 755` on the installed extension's binary only — `chmod 755 "<extension-install-dir>/hayabusa/hayabusa-3.10.0-lin-x64-gnu"`. This is a manual, per-install workaround; it does not survive a future reinstall of the unpacked extension and would need to be reapplied (or fixed upstream in the install/packaging step, e.g. `download_hayabusa.sh` or the extension packaging process, to `chmod +x` the binary automatically).

## Files created/modified

> **Note:** this section reflects the initial two-tool implementation only. `server.py`
> later grew two more tools (`analyze_coverage`, `suggest_rule`) and four `detection://`
> resources, plus three more test files — see the dated sections below ("detection://
> resources", "analyze_coverage and suggest_rule tools") for those additions, and the
> "detection-engineering skill" entry at the end of this file for the most recent addition.

- `download_hayabusa.sh` — downloads, checksum-verifies, and extracts Hayabusa into `./hayabusa/`
- `hayabusa/` — extracted Hayabusa v3.10.0 release (binary, `config/`, `rules/`)
- `server.py` — low-level MCP server (`hayabusa-mcp`); at this point in the build, registered two tools:
  - `scan_evtx` (schema: `evtx_path` required; `min_severity`, `rule_filter`, `output_format`, `max_results` optional). `call_tool` runs `run_scan()`, which invokes the Hayabusa binary (`json-timeline -f <file> -L -o <tmp>.jsonl -m <min_severity> -w -q -K -N -C`, `cwd` set to `hayabusa/`), parses the resulting JSONL, applies `rule_filter`/`max_results`/`output_format` via `_filter_findings()`, and returns findings as a JSON text content block. Raises `FileNotFoundError` for a missing EVTX file or missing binary, and `RuntimeError` on a non-zero Hayabusa exit — both surface as proper MCP `isError` results.
  - `get_hayabusa_rules` (schema: optional `keyword`). `call_tool` runs `list_rules()`, which walks `hayabusa/rules/{hayabusa,sigma}/**/*.yml`, parses each with PyYAML, optionally filters by keyword, sorts by title, and returns the rule metadata as a JSON text content block.
- `samples/CA_4624_4625_LogonType2_LogonProc_chrome.evtx` — one small (69KB) sample EVTX file used for local testing
- `test_scan_evtx.py` — local test suite driving `server.py`'s actual registered MCP handlers for `scan_evtx`; covers tool exposure, a basic scan, the severity-filtering regression, `rule_filter`, `output_format`, and `max_results`
- `test_get_hayabusa_rules.py` — local test suite for `get_hayabusa_rules`; covers tool exposure, an unfiltered listing (sanity-checks rule count and fields), keyword match/exclude, keyword case-insensitivity, and exact field values against a known bundled rule
- `.mcp.json` — project-level MCP server definition for `hayabusa-mcp`
- `.claude/settings.json` — enables `hayabusa-mcp` via `enabledMcpjsonServers`
- `requirements.txt` — added `pyyaml`
- `manifest.json` — Claude Desktop extension manifest (MCPB pattern); `command: python3`, `PYTHONPATH` pointed at vendored `lib/`
- `lib/` — vendored `mcp`, `pyyaml`, and transitive dependencies for the Claude Desktop extension (not part of the project `.venv`)

## Completed work

1. Downloaded and checksum-verified the official Hayabusa release; confirmed the binary runs
2. Scaffolded `server.py` with the low-level MCP API and wired it up via `.mcp.json`
3. Implemented `scan_evtx`'s scan logic (Hayabusa `json-timeline` + JSONL parsing)
4. Verified `scan_evtx` live through Claude Code against the sample EVTX file
5. Found and fixed the severity-filtering bug (relative-path resolution against the wrong `cwd`), with regression tests
6. Added `rule_filter`, `output_format` (`summary`/`full`), and `max_results` parameters, with tests for each
7. Added the `get_hayabusa_rules` tool (keyword-filterable rule listing), with tests
8. All 12 tests pass (7 in `test_scan_evtx.py`, 5 in `test_get_hayabusa_rules.py`)

## Hayabusa version and checksum verification

- Version: **v3.10.0** ("Independence Day Release"), pinned in `download_hayabusa.sh`
- Asset: `hayabusa-3.10.0-lin-x64-gnu.zip` (Linux x86_64, glibc build)
- Checksum: verified against GitHub's SHA-256 digest for the asset —
  `5879131758c142b0d30d14e4b3f4019155507384d22ad1ce55868670325a071c` — result: **OK**
- Binary sanity check: `./hayabusa/hayabusa-3.10.0-lin-x64-gnu help` runs successfully and reports **"Hayabusa v3.10.0 - Independence Day Release"**

## Local test results

```
$ .venv/bin/python test_scan_evtx.py
PASS: sample_file_present
PASS: list_tools_exposes_scan_evtx
PASS: call_scan_evtx_against_sample (1 findings returned)
PASS: low_finding_present_at_informational_and_low_but_not_above
PASS: rule_filter_matches_and_excludes
PASS: output_format_summary_vs_full
PASS: max_results_limits_findings

All tests passed.

$ .venv/bin/python test_get_hayabusa_rules.py
PASS: list_tools_exposes_get_hayabusa_rules
PASS: call_get_hayabusa_rules_no_keyword_returns_many_rules (4958 rules)
PASS: keyword_matches_and_excludes
PASS: keyword_filter_is_case_insensitive
PASS: rules_have_expected_fields

All tests passed.
```

## .mcp.json config status

- `.mcp.json` defines `hayabusa-mcp`, command: `.venv/bin/python`, args: `server.py` (both absolute paths under this project)
- `.claude/settings.json` lists `hayabusa-mcp` in `enabledMcpjsonServers` (auto-approved for this project)
- Confirmed working live: both `scan_evtx` and `get_hayabusa_rules` have been called through the connected MCP server in a Claude Code session and returned real Hayabusa results

## detection:// resources (2026-07-10)

Added four read-only MCP resources on top of the existing two tools, entirely additive — `run_scan`, `_filter_findings`, `list_rules`, `list_tools`, and `call_tool` are unchanged (`git diff` on `server.py` across all three commits shows additions only):

- `detection://rules` — compact JSON index (`resource_id`, `id_source`, `title`, `level`), capped at 500 rows with `truncated`/`total_rules` flags.
- `detection://rules/{rule_identifier}` — full YAML text of one rule, byte-faithful (not re-parsed).
- `detection://rules/by-technique/{technique_id}` — rules tagged with a MITRE technique, with parent-inclusive/sub-technique-exact matching semantics and an explicit `match_type` (`direct` vs `inherited_subtechnique`) per rule.
- `detection://attack/techniques/{technique_id}` — local coverage facts (`covered`/`not_covered`, match count) only; deliberately does **not** include a technique name/tactic/description, since no ATT&CK dataset is bundled anywhere in this repo (`hayabusa/config/mitre_tactics.txt` only maps tactics, never individual techniques) — a real, flagged product gap rather than a silently-omitted field.

Empirically verified before/while implementing (not assumed):
- 4,961 rule `.yml` files exist; `list_rules()` successfully parses 4,958 (3 multi-document files are already silently skipped — an existing, unchanged limitation).
- Bare filenames collide across subdirectories (hundreds of duplicate basenames), so rule identity uses each rule's own YAML `id:` (UUID) instead — confirmed unique across all 4,958 parsed rules today.
- A deterministic `sha256`-of-path fallback (not Python's per-process-randomized `hash()`) covers the (currently nonexistent) case of a rule missing `id:`; fallback identifiers are marked `id_source: "fallback"` vs `"yaml"`.
- Duplicate identifiers, if they ever occur, are excluded from direct lookup (never silently resolved to one rule), reported via a `RuntimeWarning` and in the index's `duplicate_ids` field, and raise `ValueError` on a direct lookup attempt.
- A bare-parent `T1059` query matches 603 rules today, and the fixture rule `4973dea2-3985-affa-babc-f0c00821d2a1` (tagged only `attack.t1003`, no sub-technique tag) proves parent/sub-technique matching is a real scenario, not a hypothetical — this justified both the parent-inclusive matching design and the 500-row response cap (measured: ~150 bytes/row × 500 ≈ 75 KB, well under the limit that a ~300-row broader response already exceeded per the `get_hayabusa_rules` note above).

New test suite `test_resources.py` (21 cases, all passing) exercises the actual registered `ListResourcesRequest`/`ListResourceTemplatesRequest`/`ReadResourceRequest` handlers, following the same convention as `test_scan_evtx.py`/`test_get_hayabusa_rules.py`. One asymmetry worth noting: `read_resource`'s SDK wrapper has no try/except (unlike `call_tool`), so exceptions raised there surface as JSON-RPC protocol errors rather than `isError=True` content results — tests catch them directly rather than inspecting `isError`.

`test_scan_evtx.py` (7 cases) and `test_get_hayabusa_rules.py` (5 cases) still pass unchanged, confirming both existing tools are unaffected. No changes were needed to `requirements.txt`, `manifest.json`, `.mcp.json`, or `.claude/settings.json` — all new code uses only the stdlib plus already-declared dependencies, and resources are just new handlers in the same `server.py` entry point used by both deployment targets.

## Pre-push review (2026-07-10)

- **4 commits created** on `main`, ahead of `origin/main` by exactly 4 (0 behind): `e133355` (rule index cache + `detection://rules`), `3e3404f` (`detection://rules/{rule_identifier}`), `4cbc3c8` (by-technique + coverage resources), `24ff9ea` (README/HANDOFF docs).
- **33 tests passing**: 7 in `test_scan_evtx.py` + 5 in `test_get_hayabusa_rules.py` (both unchanged from before this work) + 21 in the new `test_resources.py`, all exit 0.
- **Tools and resources verified live, in-process**: `list_tools` still returns `scan_evtx`/`get_hayabusa_rules`, and `get_hayabusa_rules(keyword="mimikatz")` returns successfully (`isError=False`); `list_resources` returns `detection://rules`, `list_resource_templates` returns all three parameterized templates, and a live read of `detection://rules` succeeds.
- **Repository confirmed safe to push**: `git status` clean; diff across all 4 commits scanned for emails, IPs, hostnames, secret/token/private-key patterns, and the local username/dirname — nothing found; commit author/committer and `Co-Authored-By` trailers use the repo's existing noreply addresses; only `server.py`, `test_resources.py`, `README.md`, `HANDOFF.md` were touched (no `__pycache__`, `.venv`, `hayabusa/`, `lib/`, `dist/`, or other generated artifacts committed); `.gitignore` remains adequate for this change.

(Push and post-push verification against `origin/main` were completed later in the build — see "Final live validation and project conclusion" at the end of this file for the resolved state.)

## Next step

The Claude Desktop extension is fully set up and confirmed working end-to-end: both `get_hayabusa_rules` (26 Mimikatz matches) and `scan_evtx` (absolute EVTX path, real findings) have been exercised live from Claude Desktop — see "Claude Desktop extension setup" above, including the Linux unpacked-extension `0600` binary-permission issue and its `chmod 755` workaround.

Publication cleanup is complete: machine-specific paths and username scrubbed from tracked files, `lib/` untracked (regenerated via `package_extension.sh`), sample EVTX provenance documented, `LICENSE` and `README.md` added, and git history replaced with a single sanitized initial commit. The branch has been renamed to `main`, and the working tree is clean.

Remaining:
1. Write up a Medium article covering the build process

(The GitHub repository was created and `main` pushed later in the build — see "Final live validation and project conclusion" at the end of this file.)

## analyze_coverage and suggest_rule tools (2026-07-10)

Added two new MCP tools, both **read-only**, entirely additive on top of the existing two tools and four resources — no existing function, tool, or resource was modified:

- `analyze_coverage` — accepts a batch of MITRE technique IDs and returns per-ID binary coverage (`covered`/`not_covered`) plus match count and sample rule IDs. A malformed ID in the batch is reported per-entry rather than failing the whole call.
- `suggest_rule` — accepts a single technique ID (plus an optional `title`). If already covered, returns the existing matching rules for review (`rule_template: null`). If not covered, returns a draft Sigma-style rule template as data only — **never writes anything to disk**. The template's only ATT&CK tag is the literal technique ID supplied by the caller; no technique name or tactic is invented.

Both tools are built on the same `_matches_for_technique()` helper already used by `detection://rules/by-technique/{id}` and `detection://attack/techniques/{id}`, so there is no separate matching logic to drift out of sync.

**Tests:** `test_analyze_coverage.py` (6 cases) and `test_suggest_rule.py` (8 cases), including an explicit read-only regression guard for `suggest_rule` that snapshots every rule file's mtime before/after invocation and asserts nothing changed.

**Full regression suite: 41/41 tests passing** across all five test files (15 `test_resources.py` + 5 `test_get_hayabusa_rules.py` + 7 `test_scan_evtx.py` + 6 `test_analyze_coverage.py` + 8 `test_suggest_rule.py`). The two original tools (`scan_evtx`, `get_hayabusa_rules`) and all four existing resources were re-verified working, unchanged.

**One new local commit** exists on `main`. Diff scope confirmed limited to `server.py` (additive only) plus the two new test files; no unexpected files included. (Same clean secrets/PII/credentials/tokens/private-paths scan as the pre-push review above — see that section for the full attestation; not repeated here.)

**Known limitations (by design, not bugs):**
- Coverage is strictly **binary** (`covered`/`not_covered`) in both tools. There is no partial/fractional/percentage coverage concept, and a `covered` result says nothing about detection quality, tuning, false-positive rate, or whether a matching rule is actually enabled in a given scan profile.
- This server bundles **no ATT&CK technique-name or tactic dataset**. Technique IDs are validated only for correct `Tnnnn(.nnn)` syntax — neither tool can confirm an ID is a real MITRE technique, resolve its name/tactic, or enumerate "all techniques in tactic X". `suggest_rule`'s draft template deliberately omits a tactic tag entirely rather than guess one.

Remaining:
1. Final review
2. Exit Claude Code

(This commit was pushed to `origin/main` later in the build — see "Final live validation and project conclusion" at the end of this file for the resolved state.)

## Final live validation and project conclusion (2026-07-10)

- `analyze_coverage` was successfully live-tested through the connected MCP server.
- `suggest_rule` was successfully live-tested with `T1611`.
- `suggest_rule` remained read-only, returning a draft rule template with `TODO` fields requiring human completion and validation before any real use.
- No files were created or modified during the live tool tests.
- Implementation and validation are complete.
- The repository is clean and synchronized with `origin/main`.

## detection-engineering skill (2026-07-10)

**Status: implementation and verification complete.** Added a project-scoped skill at
`.claude/skills/detection-engineering/`, packaging the rule-authoring workflow already
supported by `analyze_coverage`/`suggest_rule`/`get_hayabusa_rules`/`scan_evtx` and the
`detection://` resources. Files added:

- `SKILL.md` — frontmatter with concrete activation triggers ("Sigma rule", "Hayabusa
  detection rule", "MITRE ATT&CK coverage", "EVTX detection rule") plus a workflow doc:
  check existing coverage first (`analyze_coverage`/`suggest_rule`), fill in a draft using
  the schema reference, validate locally, confirm the rule fires via `scan_evtx`, re-check
  coverage.
- `scripts/validate_rule.py` — a local structural/schema validator (stdlib + the
  already-declared `pyyaml` dependency only, no new installs). Checks required fields
  (`title`, `id` as a real UUID, `logsource.product`, `detection` with a `condition` that
  references a defined selection/filter block, `level`, `status`), mirroring the fields
  `server.py`'s `list_rules()`/`_matches_for_technique()` already rely on so the two can't
  drift apart. CLI: `python validate_rule.py <path-to-rule.yml>`, exit 0 with `VALID: ...`
  or exit 1 with `INVALID: ...` plus a per-field reason list.
- `reference/rule-schema.md` — field cheatsheet for both rule dialects bundled in this
  repo (plain Sigma and Hayabusa-native).
- `reference/mcp-tools.md` — summary of all four tools and four `detection://` resources,
  referenced by function name (not line number, which drifts) so it stays accurate as
  `server.py` changes.
- `reference/example-rule.yml` — one minimal, hand-written, synthetic valid rule. Written
  from scratch for the skill rather than copied from `hayabusa/rules/`, since that
  directory is gitignored and won't exist in a fresh clone before `download_hayabusa.sh`
  runs — the skill's own example is self-contained and doesn't depend on it.
- `tests/test_validate_rule.py` + synthetic fixtures under `tests/fixtures/` — see test
  results below.

All new files live inside the skill directory itself (not repo root), per an explicit
preference that the skill package stay self-contained and portable.

**Bug found and fixed during testing:** the first draft of `validate_rule.py`'s
condition-reference check used a plain substring match, so a `condition: "selection_typo"`
was incorrectly accepted as referencing a `selection` block (the substring `"selection"`
matches inside `"selection_typo"`). Caught by
`test_condition_must_reference_a_defined_block`, then fixed to tokenize the condition
string and compare whole words instead of substrings. Re-run confirmed the fix.

**Documentation updates completed:**
- `CLAUDE.md` — was stale since the project's original `scan_evtx`-only goal; now lists
  all four tools (`scan_evtx`, `get_hayabusa_rules`, `analyze_coverage`, `suggest_rule`)
  and the `detection://` resources, and points to the new skill.
- `README.md` — was missing `analyze_coverage`/`suggest_rule` from both the intro and the
  tool list even though they were already implemented; now documents all four tools and
  links to the skill.
- `HANDOFF.md` (this file) — the stale "Files created/modified" tool inventory was
  annotated as reflecting only the initial two-tool state (with a pointer to the later
  sections that added the rest); the four non-reconciled "push to origin" status blocks
  accumulated across earlier dated sections were collapsed into single resolved
  statements; the duplicated secrets/PII-scan attestations were merged into one.

**Test results — new skill tests, `test_validate_rule.py` (6/6 passing):**

```
$ .venv/bin/python .claude/skills/detection-engineering/tests/test_validate_rule.py
PASS: example_rule_is_valid
PASS: missing_fields_rule_fails_with_clear_reasons
PASS: malformed_yaml_fails_gracefully
PASS: missing_file_reports_not_found
PASS: condition_must_reference_a_defined_block
PASS: unknown_level_is_flagged

All tests passed.
```

Cases cover: a valid rule passes; a rule missing `id`/`detection`/`level` fails with a
clear per-field reason; a rule with malformed/unparseable YAML fails gracefully without
leaking a raw stack trace; a missing file is reported cleanly; a `condition` that doesn't
reference any defined selection/filter block is caught; an unrecognized `level` value is
flagged.

**Full regression check — all 5 existing repo-root suites re-run after the skill was
added, 41/41 passing, zero regressions:**

```
test_scan_evtx.py            — 7/7  passing
test_get_hayabusa_rules.py   — 5/5  passing
test_resources.py            — 15/15 passing
test_analyze_coverage.py     — 6/6  passing
test_suggest_rule.py         — 8/8  passing
```

`validate_rule.py` was also sanity-checked directly via its CLI: `VALID` (exit 0) against
`reference/example-rule.yml`, and `INVALID` (exit 1, with clear per-field reasons) against
both synthetic invalid fixtures.

**Remaining limitations / follow-up items (by design, not defects):**
- `validate_rule.py` checks structure only — it cannot confirm a rule's detection logic is
  correct, low-noise, or that it will actually fire against real data. `scan_evtx` against
  a real or sample EVTX is still required to confirm behavior, as the skill's own workflow
  doc states.
- The two known product gaps already documented above (binary-only coverage; no bundled
  ATT&CK technique-name/tactic dataset) apply equally to this skill's guidance, and
  `SKILL.md` explicitly tells the workflow not to paper over either one.
- No CI/lint automation was added for the new skill files — `validate_rule.py` and its
  tests are run manually, matching how the rest of this repo's tests are run today.
- Skill activation itself (does the skill actually get picked up on a natural-language
  detection-engineering request, without misfiring on unrelated prompts) was checked via
  the CLI/test-suite paths above, not yet re-verified in a fresh interactive session — a
  reasonable next manual check before relying on it day-to-day.

**Sensitive-data check for this change:** every new/modified file (`SKILL.md`,
`validate_rule.py`, the reference files, the tests and fixtures, and the `CLAUDE.md`/
`README.md`/`HANDOFF.md` edits) was swept for credentials, tokens, API keys, private keys,
real hostnames/usernames/IPs, and machine-specific absolute paths — none found. All example
and fixture rule content is synthetic (invented titles/IDs/descriptions), consistent with
the clean sensitive-data sweep already on record for the rest of this repository.
`requirements.txt` was not modified — no new third-party dependency was introduced.

**The repository is ready for final review and a checkpoint commit.** No commit has been
made as part of this change.

## investigate-evtx command (2026-07-12)

**Status: implementation and initial verification complete; not yet committed.** Added the
first project-level slash command, `.claude/commands/investigate-evtx.md`, which drives the
existing four MCP tools plus the `detection://` resources to turn an EVTX scan into an
Obsidian-compatible investigation note under `investigations/`.

**Binding decisions (confirmed with the user before implementation):**
- Invocation: `/investigate-evtx <evtx-path> [severity]`.
- Default `min_severity` is `medium`; an optional override is normalized (trim + lowercase)
  and validated against the exact `scan_evtx` enum (`informational|low|medium|high|critical`)
  *before* any scan call — invalid values are rejected with no tool call made.
- Output lives under `investigations/` at repo root; `.gitignore` was updated (one-time,
  separate change: a single added line, `investigations/`) since notes can contain real
  hostnames/usernames/IPs/process paths pulled from analyzed EVTX files.
- "Related Investigations" is populated only by **verified** exact overlap on at least one
  MITRE technique ID or RuleID between the current run and existing `investigations/*.md`
  frontmatter (`techniques:`/`rule_ids:` keys) — never a fuzzy/title-based match, and never
  same-source-file alone.

**Key design fact discovered during planning (not assumed):** `scan_evtx` findings carry
only a `RuleID`, never MITRE tags directly. The command resolves
`RuleID -> attack.* tags` via `ReadMcpResourceTool` against `detection://rules/{RuleID}`
(exact-ID resource lookup), added to `allowed-tools` alongside the four
`mcp__hayabusa-mcp__*` tools, rather than a keyword-search-then-filter through
`get_hayabusa_rules` (less precise, since rule titles aren't guaranteed unique across
~4,960 bundled rules).

**Verification performed (manual walkthrough of the command's own steps, tool-by-tool,
against `samples/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`):**

| Test | Result |
|---|---|
| Low-severity override (`... low`) | PASS — 1 finding, `RuleID e87bd730-df45-4ae9-85de-6c75369c5d29`. Rule's `tags:` list is empty; correctly reported as "no ATT&CK tags for this rule," and `analyze_coverage` correctly **skipped** (its schema requires `minItems:1`) rather than called with an empty list. |
| Invalid severity (`... bogus`) | PASS — rejected with the exact usage/enum message, before any `scan_evtx` call. |
| Mixed-case severity (`... Medium`) | PASS — normalized to `medium` and accepted. |
| Medium (default) severity | PASS — 0 findings (sample's only event is `low`-level); handled as a non-error, audit-trail note written rather than treated as a failure. |
| Filename collision | PASS — second note (`...-2.md`) correctly suffixed rather than overwriting the first. |
| `.gitignore` exclusion | PASS — both generated notes confirmed `!!` (ignored) via `git status --ignored`, never staged/tracked. |

Generated during verification: `investigations/2026-07-12-CA_4624_4625_LogonType2_LogonProc_chrome.md`
(low-severity run) and `investigations/2026-07-12-CA_4624_4625_LogonType2_LogonProc_chrome-2.md`
(medium-severity run) — both git-ignored, neither committed.

**Full regression check — all 6 existing suites re-run after this change, 41/41 passing,
zero regressions** (`test_scan_evtx.py` 7/7, `test_get_hayabusa_rules.py` 5/5,
`test_analyze_coverage.py` 6/6, `test_suggest_rule.py` 8/8, `test_resources.py` 15/15,
skill's `test_validate_rule.py` 6/6). No test files were added or modified for the new
command, since it is a prompt/instruction file, not executable Python — there is nothing in
`server.py` for it to exercise via the existing test convention.

**Not yet verified (remaining step, flagged not hand-waved):** the bundled sample has no
rule with real `attack.*` tags, so the full happy path — a finding resolving to a real
technique, `analyze_coverage` returning `covered` results, and two notes cross-referencing
each other via a verified technique/RuleID overlap producing an actual `[[wikilink]]` — has
not been exercised end-to-end. Confirmed as a working reference point only
(`get_hayabusa_rules(keyword="Important Log File Cleared")` -> tags
`[attack.defense-evasion, attack.t1070.001]`; `analyze_coverage(["T1070.001"])` ->
`covered`, `matching_rule_count: 4`), not run through the command itself. Needs a
tagged-rule-triggering EVTX (real or synthetic) to close out.

**Other known, by-design limitations carried over from existing tools/resources** (not new):
binary-only coverage; no bundled ATT&CK technique-name/tactic dataset, so every
`[[Txxxx]]` wikilink in a generated note is expected to render as unresolved/orphan in
Obsidian unless the user's vault separately maintains per-technique pages. The command's own
body text calls this out inline rather than papering over it.

**Sensitive-data check for this change:** `.claude/commands/investigate-evtx.md` and the
`.gitignore` addition were swept for credentials, tokens, API keys, private keys, real
hostnames/usernames/IPs, and machine-specific absolute paths — none found (confirmed via
targeted grep, no matches). The two generated `investigations/*.md` test notes contain only
fields already present in the repo's own public/synthetic sample fixture (e.g.
`Computer: MSEDGEWIN10`, a known SANS-style sample artifact) — not real incident data — and
are git-ignored regardless.

**The repository is ready for staged-diff review and a checkpoint commit.** No commit has
been made as part of this change.

**Post-staging update:** `.gitignore`, `HANDOFF.md`, and `.claude/commands/investigate-evtx.md`
were staged via `git add` and the full staged diff (`git diff --cached`) was reviewed for
secrets, tokens, credentials, usernames, email addresses, private/machine-specific paths,
sensitive log data, and unrelated changes — no concerns found; every hunk was attributable to
one of the three intended files. Generated `investigations/*.md` test notes remain confirmed
`!!` (git-ignored), never staged. No commit has been made.

## /triage command and techniques/ knowledge base (2026-07-13)

**Status: implementation and manual verification complete; not yet committed.**

Added a second project-level slash command, `.claude/commands/triage.md`, alongside a new
tracked directory convention, `techniques/`, for reusable MITRE ATT&CK technique reference
notes. No new skill was created — `.claude/skills/` still contains only the pre-existing
`detection-engineering` skill.

**Classification:** both `/investigate-evtx` and `/triage` are project-level slash
commands — plain Markdown files under `.claude/commands/`, each with
`description`/`argument-hint`/`allowed-tools` frontmatter, interpreted as instructions at
runtime rather than executable code. Neither has, or can have, an automated test in this
repo's existing convention (test files exercise `server.py`'s registered MCP handlers
directly; a slash command has no equivalent handler to invoke programmatically — confirmed
this build when invoking `/triage` via the generic `Skill` tool with a positional `args`
string did not perform `$1`/`$2`/`$3` substitution, unlike a human typing the command
directly at the interactive prompt).

**Purpose and how the two commands differ:**
- `/investigate-evtx <evtx-path> [severity]` (existing, unchanged) — scans an EVTX file,
  resolves ATT&CK tags, and writes a general investigation note under `investigations/`,
  cross-linking prior investigations on verified technique/RuleID overlap.
- `/triage <evtx-path> [severity] [case-id]` (new) — runs the same
  scan → resolve-tags → coverage pipeline, but adds an optional case ID, requires assigning
  exactly one triage outcome (`escalate`, `investigate`, `investigate further`,
  `likely benign`, `insufficient evidence`), writes to a separate `investigations/triage/`
  directory, cross-links against three corpora (other triage notes, `/investigate-evtx`
  notes, and technique notes) instead of one, and additionally syncs a tracked
  `techniques/<ID>.md` reusable knowledge-base note for every technique it resolves.
  `/investigate-evtx` remains the lighter-weight, general note-taking workflow; `/triage` is
  the case-oriented, outcome-driven workflow with an aggregate cross-case knowledge base as a
  side effect.

**MCP tools/resources used (identical set for both commands, nothing new added):**
`mcp__hayabusa-mcp__scan_evtx`, `get_hayabusa_rules`, `analyze_coverage`, `suggest_rule`,
plus `ReadMcpResourceTool` against `detection://rules/{RuleID}`,
`detection://rules/by-technique/{id}`, and `detection://attack/techniques/{id}`, and the
built-in `Read`/`Write`/`Glob` tools for note I/O.

**Binding decisions on `/triage`'s arguments (confirmed with the user before
implementation):**
- Default `min_severity` is `medium`, same as `/investigate-evtx`.
- An optional severity override is trimmed, lowercased, and validated against the exact
  `scan_evtx` enum (`informational|low|medium|high|critical`) *before* any scan call; a
  non-matching value is rejected outright with no tool call made.
- An optional `case_id` (third argument) must match `^[A-Za-z0-9_-]{1,64}$` exactly —
  letters, digits, hyphens, underscores only. Anything else (path separators, `..`
  traversal, whitespace, shell metacharacters, `@`/email-shaped values) is **rejected
  outright, before any scan call** — never silently stripped or sanitized. When present and
  valid, `case_id` becomes both a filename prefix
  (`investigations/triage/<case_id>-<YYYY-MM-DD>-<evtx-basename>.md`) and a frontmatter
  field.

**Output-location decision:** `investigations/triage/` needed **no new `.gitignore`
entry** — the existing bare `investigations/` rule (added for `/investigate-evtx`, see the
2026-07-12 section above) already ignores the whole subtree recursively. Confirmed directly
via `git check-ignore -v`.

**`techniques/` — new tracked knowledge-base directory:**
- Unlike every other generated artifact in this repo so far, `techniques/<TechniqueID>.md`
  is **tracked in git**, not ignored — a deliberate, confirmed decision to make it a shared,
  reusable ATT&CK reference.
- Permitted content only: technique ID, technique name/tactic placeholders (never invented —
  no ATT&CK name/tactic dataset is bundled anywhere in this project), related Rule
  IDs/titles/levels, aggregate coverage status, and reusable/generic analyst guidance.
- Explicitly forbidden, enforced structurally in the command (technique-note content is
  sourced only from `get_hayabusa_rules`/`detection://rules/by-technique`/`analyze_coverage`/
  `detection://attack/techniques`, never from a `scan_evtx` finding field): case-specific
  data, raw event fields, hostnames, usernames, private paths, timestamps from
  investigations, credentials, secrets, or other PII. A "Linked Investigations" field is a
  bare aggregate count, never a filename, date, case ID, or link back to a specific
  (gitignored) investigation/triage note — content flows one way, from case-specific notes
  into the generic knowledge base, never the reverse.

**Cross-referencing rule (same discipline as `/investigate-evtx`, extended to three
corpora):** a triage note links to another triage note, an investigation note, or a
technique note only on a **verified, exact, case-insensitive match** on at least one MITRE
technique ID or RuleID between frontmatter fields — never a fuzzy or title-based match, and
never same-source-file alone. Technique notes never link back to specific investigations.

**Managed-section sync / non-destructive update behavior:** each `techniques/<ID>.md` has
machine-owned sections (`## Related Rules`, `## Coverage Status`, `## Linked Investigations`
count) that are fully replaced on every sync, and human-owned fields/sections
(`technique_name`, `tactic` frontmatter, `## Analyst Notes`) that are set once at file
creation and never rewritten afterward. Update logic operates by locating fixed
`## <Heading>` anchor lines and replacing only the recognized machine-owned ranges, leaving
everything else byte-identical.

**Verification performed — six manual dry-run tests, plus direct file-mechanics
verification (no automated harness exists for slash-command behavior; see below):**

| Test | What it validated | Result |
|---|---|---|
| 1. Default severity, no case ID | Zero-finding path; `insufficient evidence` outcome; no-case-ID filename scheme | PASS |
| 2. `low` severity, no case ID | One-finding path with no ATT&CK tags; `likely benign` outcome; verified-overlap cross-link to the existing `/investigate-evtx` note by RuleID (and correct *exclusion* of the non-overlapping sibling note) | PASS |
| 3. `low` severity + case ID | Case-ID filename prefix + frontmatter field; triage-to-triage cross-linking | PASS |
| 4. Case ID = path-traversal string | Rejected before any scan call, zero tool calls made | PASS |
| 5. Four further malformed case IDs (path separator, whitespace, email address, shell metacharacters) | Same reject-before-scan behavior across the full forbidden-character space | PASS |
| 6. Exact re-run of test 3 | Filename collision correctly resolved with a `-2` suffix rather than overwriting; cross-linking scaled to multiple overlapping prior notes | PASS |

Separately (since the bundled sample EVTX only ever triggers a rule with no ATT&CK tags, so
the six dry-run tests above could not exercise the `techniques/` sync path), the sync
algorithm's file mechanics were verified directly, without a live scan, using a
hand-selected real bundled rule/technique pair — `T1134.005` (rule
`5335aea0-f1b4-e120-08b6-c80fe4bf99ad`, "Addition of SID History to Active Directory
Object"), chosen specifically for a clean 1:1 technique-to-rule mapping (`analyze_coverage`
reports exactly 1 matching rule, `covered`): first-time creation (including confirming
`Write` auto-creates the `techniques/` parent directory), a second sync correctly
incrementing the aggregate count and refreshing the machine-owned sections, a hand-edit of
the Analyst Notes section with synthetic guidance text to simulate real analyst content, and
a third sync confirming that hand-edited section plus the technique-name/tactic placeholders
came back byte-for-byte unchanged. A subsequent content sweep of the generated file for
hostnames, usernames, timestamps, paths, and other sensitive patterns found nothing.

**Temporary test artifacts removed:** all four generated `investigations/triage/*.md` notes
from the six dry-run tests and the one `techniques/*.md` file used for direct
sync-mechanics verification were deleted after review and explicit approval, since their
content (fabricated aggregate counts, synthetic analyst text, test-only case IDs) did not
reflect real usage. `investigations/triage/` and `techniques/` are both currently empty;
they will be recreated automatically the next time either command actually writes to them.

**Full regression check — automated components:** all 6 existing suites re-run after this
change, **47/47 passing, zero regressions** (`test_scan_evtx.py` 7/7,
`test_get_hayabusa_rules.py` 5/5, `test_resources.py` 15/15, `test_analyze_coverage.py` 6/6,
`test_suggest_rule.py` 8/8, skill's `test_validate_rule.py` 6/6). This confirms the MCP
server logic underlying both slash commands — every tool and resource `/triage` and
`/investigate-evtx` compose — is unaffected. No test files were added or modified for
`/triage` itself, for the same reason as `/investigate-evtx`: it's a prompt/instruction
file, not executable Python, so there's nothing in `server.py` for a new test to exercise.

**Manually verified, not automated (no slash-command test harness exists in this repo):**
all `/triage`-specific behavior — argument parsing and case-ID validation, severity
default/override/rejection, outcome assignment, verified-overlap cross-linking across three
corpora, filename collision handling, and the entire `techniques/` create/update/preserve
sync algorithm — was validated by manually walking through the command's own documented
steps and calling the same underlying MCP tools/resources directly, exactly as
`/investigate-evtx` was validated when it was first built (see the 2026-07-12 section
above).

**Remaining limitations / optional future work (by design, not defects):**
- The "investigate" vs. "investigate further" outcome boundary has no deterministic
  tie-break beyond "pick the conservative option and record the alternative" — different
  runs may reasonably disagree on a borderline case.
- No locking/atomicity: `Glob`-then-`Write` and `Read`-then-`Write` are not transactional,
  so a concurrent `/triage` run touching the same `techniques/<ID>.md` could lose an update
  (last-write-wins). Inherent to prompt-orchestrated file operations, not solved here.
- `techniques/<ID>.md`'s `linked_investigations_count` is an approximate aggregate signal
  (it counts qualifying `/triage` runs, not deduplicated unique investigations — re-running
  `/triage` on the same EVTX increments it again), a deliberate tradeoff to avoid storing
  any identifying key that could leak gitignored-investigation details into the tracked
  file.
- The "never copy a `scan_evtx` finding field into `techniques/`" rule is enforced by
  instruction within the command file, not by code — worth an occasional manual spot-check
  of `techniques/*.md` before pushing, same spirit as this repo's existing pre-commit
  sensitive-data sweeps.
- No pruning/archival mechanism exists for `techniques/` notes over time; out of scope for
  this change.
- The mixed covered/not_covered, multi-severity "investigate vs. investigate further"
  scenario (one of the originally planned test cases) was not exercised, since no fixture
  EVTX matching that pattern was available — a reasonable follow-up if a richer sample
  becomes available.

**Sensitive-data check for this change:** `.claude/commands/triage.md` was swept for
credentials, tokens, API keys, private keys, real hostnames/usernames/IPs, and
machine-specific absolute paths — none found. All test artifacts generated during
verification (case IDs, technique/rule identifiers, synthetic analyst text) were synthetic,
not real case data, and have since been deleted; none were committed.

**The repository is ready for diff review and a checkpoint commit.** No commit has been
made as part of this change.

**Next steps (checkpoint, superseded by the "Hooks" section below):**
1. Review the full diff (`git diff` / `git status`).
2. Restage `HANDOFF.md` after this update (`git add HANDOFF.md`) alongside
   `.claude/commands/triage.md`.
3. Review the staged diff (`git diff --cached`) for secrets, tokens, credentials,
   usernames, emails, private paths, and unrelated changes.
4. Commit.
5. Verify (confirm `git status` is clean and the commit contains only the intended files).
6. Exit Claude Code.
7. Push `main` to `origin` from the regular terminal, to maintain this repo's established
   manual-push workflow.

## Hooks: SessionStart/PreToolUse/PostToolUse (2026-07-14)

**Status: implementation and verification complete; not yet committed.** Added three Claude
Code hooks under `.claude/hooks/`, registered in `.claude/settings.json`, plus a shared
`_common.py` helper (project-root resolution and stdin-JSON parsing, used by all three so
that logic isn't duplicated three times).

**Binding decision (confirmed with the user before implementation):** every hook is
strictly additive safety — each can only `deny` on top of Claude Code's existing
manual-approval flow, or give Claude read-only advisory feedback. None may ever emit
`permissionDecision: "allow"`. This means manual approval for every ordinary file change and
command is unchanged; the only new hard-stop is the narrow sensitive-path denylist below.

**Syntax verified against current official docs, not assumed or copied from a course:**
installed Claude Code CLI was `2.1.209` at implementation time. Current hook syntax (event
names, the `matcher` + `hooks`-array nesting, the `hookSpecificOutput` schema) was checked
two independent ways — a research subagent, and a direct `WebFetch` of
`https://code.claude.com/docs/en/hooks` — before writing any hook, specifically to catch
outdated patterns a course or tutorial might still teach. The one concrete trap avoided:
older material commonly shows a **top-level `"decision": "approve"/"block"` field for
PreToolUse** — current syntax supersedes this with
`hookSpecificOutput.permissionDecision: "allow"/"deny"/"ask"/"defer"`, which is what
`protect_sensitive_paths.py` actually uses (never `"allow"`, per the binding decision
above). The other adaptation: flat, matcher-less hook registration (also common in older
examples) was avoided in favor of the current `matcher` + `hooks`-array nesting used
throughout `.claude/settings.json`.

**Files added/changed (consolidated):**
- `.claude/hooks/_common.py` — new
- `.claude/hooks/session_start_check.py` — new
- `.claude/hooks/protect_sensitive_paths.py` — new
- `.claude/hooks/validate_rule_hook.py` — new
- `.claude/hooks/tests/test_hooks.py` — new, 32 cases
- `.claude/settings.json` — modified, adds the `hooks` key
- `README.md` — modified, adds Slash commands and Hooks sections (the latter covering
  behavior, prerequisites, setup, testing, restart, troubleshooting, and user-facing
  limitations)
- `HANDOFF.md` — this section

**What was added (detail):**
- `session_start_check.py` (SessionStart, matcher `""`, always exits 0 since SessionStart
  cannot block a session regardless) — reports Hayabusa binary presence/executable bit
  (catches the exact Linux unpacked-extension `chmod 0600` regression documented above under
  "Claude Desktop extension setup"), `pyyaml` importability, and whether `hayabusa-mcp` is
  still listed in `enabledMcpjsonServers`, via `hookSpecificOutput.additionalContext`.
- `protect_sensitive_paths.py` (PreToolUse, matcher `Write|Edit`) — denies (never allows)
  writes resolving into `.git/`, `.claude/settings.json`/`.claude/settings.local.json` (the
  hook config itself), `hayabusa/` (checksum-verified download, regenerated by
  `download_hayabusa.sh`), `lib/` (vendored extension deps, regenerated by
  `package_extension.sh`), credential directories (`.ssh/`, `.aws/`, `.gnupg/`),
  credential/secret/key-shaped files (`.env` and variants except known templates, `id_rsa`
  and friends, `credentials`/`credentials.json`, `.npmrc`, `.netrc`, and
  `.pem`/`.key`/`.pfx`/`.p12`/`.crt`/`.cer`), or any path resolving outside the project root.
  Directory rules match at any depth in the path (see the follow-up review below), and all
  comparisons are case-folded. Everything else produces no output, so the normal
  manual-approval prompt fires unchanged.
- `validate_rule_hook.py` (PostToolUse, matcher `Write|Edit`) — imports
  `validate_rule_file()` directly from
  `.claude/skills/detection-engineering/scripts/validate_rule.py` (the same `sys.path`
  pattern the skill's own `tests/test_validate_rule.py` already uses) rather than
  re-implementing the schema check. Skips files under `hayabusa/` or any `tests/fixtures/`
  path, and skips anything that doesn't look Sigma/Hayabusa-rule-shaped (a `logsource` or
  `detection` key present — see the bug-fix note below for why both keys are checked). On a
  validation failure, emits `{"decision": "block", "reason": ...}` with the exact same
  per-field error strings `validate_rule.py` already produces, since the file is already
  written by the time PostToolUse fires — this is feedback for self-correction, not an
  undo.
- `.claude/hooks/tests/test_hooks.py` — 15 cases, following the same convention as every
  other `test_*.py` in this repo (standalone script, `PASS:`/`All tests passed.`, no
  pytest), importing the hook scripts' pure functions directly rather than driving them
  through stdin/stdout.

**Bug found and fixed during testing:** the first draft of `validate_rule_hook.py`'s
`looks_like_rule()` heuristic required a `detection` key to treat a file as
rule-shaped — but the skill's own `tests/fixtures/missing_fields.yml` fixture is missing
exactly that key (it's testing the missing-`detection`-field path), so a real-world rule
missing `detection` would have been silently skipped by the hook instead of flagged. Caught
by manually running the hook end-to-end against a copy of that fixture placed at an
ordinary (non-fixture) path and observing no output. Fixed by matching on `logsource` **or**
`detection` instead of requiring the latter; a
`test_looks_like_rule_true_for_rule_missing_detection_key` case was added to guard the
regression, and the end-to-end manual run was repeated and confirmed to now emit the
expected `decision: block` with all three missing-field reasons.

**Verification performed:**

| Test | Result |
|---|---|
| `.claude/hooks/tests/test_hooks.py` (new; grew to 32/32 across the two follow-up review rounds below) | PASS |
| Full existing regression suite re-run unchanged | PASS — 41/41 (`test_scan_evtx.py` 7/7, `test_get_hayabusa_rules.py` 5/5, `test_resources.py` 15/15, `test_analyze_coverage.py` 6/6, `test_suggest_rule.py` 8/8, skill's `test_validate_rule.py` 6/6) |
| Live CLI smoke test, `session_start_check.py` | PASS — reported `hayabusa-3.10.0-lin-x64-gnu present and executable`, `pyyaml importable`, `hayabusa-mcp enabled` against this repo's real state |
| Live CLI smoke test, `protect_sensitive_paths.py` against `.claude/settings.json` | PASS — denied with a specific reason |
| Live CLI smoke test, `protect_sensitive_paths.py` against an ordinary path (`techniques/T1003.md`) | PASS — no output, exit 0 (falls through to normal approval) |
| Live CLI smoke test, `validate_rule_hook.py` against a valid rule (`reference/example-rule.yml`) | PASS — no output |
| Live CLI smoke test, `validate_rule_hook.py` against an invalid rule copy at an ordinary path | PASS — `decision: block` with all three missing-field reasons, matching `validate_rule.py`'s own wording exactly |

**Follow-up review round 1: denylist hardening.** A manual security review of
`protect_sensitive_paths.py` against a fixed checklist (deny-only invariant, message-leak
safety, path-handling edge cases, denylist coverage, overbreadth, test coverage) found the
original denylist (`.git/`, hook config, `hayabusa/`, `lib/`, outside-root) covered only this
project's own infrastructure — with no coverage at all for `.env` files, private keys,
certificates, SSH material, or generic credentials files. Fixed by adding
`CREDENTIAL_DIR_PREFIXES` (`.ssh`, `.aws`, `.gnupg`), `SENSITIVE_FILE_NAMES` (`.env`,
`.npmrc`, `.netrc`, `id_rsa`/`id_ed25519`/`id_ecdsa`/`id_dsa`,
`credentials`/`credentials.json`), an `.env.*` variant rule with an explicit exemption for
known templates (`.env.example`/`.env.sample`/`.env.template`), `SENSITIVE_EXTENSIONS`
(`.pem`/`.key`/`.pfx`/`.p12`/`.crt`/`.cer`), and case-folded comparisons throughout. The same
review also found the "outside the project root" denial reason embedded the full resolved
absolute path — on this machine that would include the local username via the home
directory — while every other reason only ever referenced repo-relative strings; fixed by
making that one message a fixed, path-free string. 17 new test cases were added covering
every new pattern, absolute-path inputs (both in-repo-sensitive and outside-root), mixed-case
variants, a real symlink-into-`hayabusa/` case, and an explicit anti-overbreadth guard
(ordinary source/test/doc files, including a `docs/api-key-rotation.md` near-miss, still pass
through). No existing repo file was found to collide with any new pattern (checked via `find`
before writing the patterns).

**Follow-up review round 2: nested-path depth bug.** A second review of the round-1 diff
found that the directory-based checks (`SENSITIVE_DIR_PREFIXES` and
`CREDENTIAL_DIR_PREFIXES`) only compared the path's first component
(`rel.parts[0]`) against the denylist — so a sensitive directory nested anywhere
below the top level (e.g. `some/nested/.ssh/authorized_keys`,
`some/nested/hayabusa/rules/x.yml`) was invisible to the check and fell through as
unblocked. Confirmed exploitable by calling `classify()` directly against four such paths
before the fix — all four returned no denial. This affected the *original* `.git`/`hayabusa`/
`lib` rules too, not just the round-1 additions; it predates round 1 but wasn't caught until
this pass. Fixed by checking every path component (`for part in rel.parts`) instead of only
`parts[0]`; re-running the same four probe paths post-fix confirmed all are now denied, and
the existing anti-overbreadth tests were re-run to confirm no ordinary file newly regressed.
Two new test cases (`test_protect_sensitive_paths_denies_nested_credential_dirs`,
`test_protect_sensitive_paths_denies_nested_repo_internal_dirs`) guard this regression going
forward.

**`.claude/settings.json` change:** added a `"hooks"` key registering all three hooks, each
invoked as `${CLAUDE_PROJECT_DIR}/.venv/bin/python ${CLAUDE_PROJECT_DIR}/.claude/hooks/<script>.py`
with a 10s timeout. This is the actual trust-boundary change in this update — from this
commit on, every `Write`/`Edit` and every session start in this repo triggers local Python
execution automatically for anyone who clones it. Kept in the shared, git-tracked
`.claude/settings.json` (not `.claude/settings.local.json`) since these hooks are meant to
protect every clone of this repo, not just this machine.

**Known limitations (by design, not defects):**
- `protect_sensitive_paths.py` only covers `Write`/`Edit`. A `Bash` command that mutates one
  of the same sensitive paths (`rm`, `mv`, redirection) is not covered by this hook — Claude
  Code's own manual approval for `Bash` still applies regardless, so this is a
  defense-in-depth gap, not a regression from today's behavior.
- `validate_rule_hook.py`'s `looks_like_rule()` heuristic (a `logsource` or `detection` key)
  could in principle both-miss an edge-case rule dialect and both-catch some unrelated YAML
  file that happens to define one of those keys; no such false positive was observed in this
  repo's own files during testing.
- No CI automation runs any of this — like every other test in this repo, `test_hooks.py` is
  run manually.

**Sensitive-data check for this change:** every new/modified file (`_common.py`,
`session_start_check.py`, `protect_sensitive_paths.py`, `validate_rule_hook.py`,
`tests/test_hooks.py`, the `.claude/settings.json` diff, and the `README.md`/`HANDOFF.md`
edits) was checked for credentials, tokens, private keys, real hostnames/usernames/emails,
and machine-specific absolute paths — none found; all paths referenced are
repo-relative or use `${CLAUDE_PROJECT_DIR}`.

**The repository is ready for diff review and a checkpoint commit.** No commit has been made
as part of this change.

**Next steps (checkpoint):**
1. Review the full diff (`git diff` / `git status`), including the now-superseded checkpoint
   list in the "Pre-push review"-adjacent section above.
2. Stage `.claude/hooks/`, `.claude/settings.json`, `README.md`, and `HANDOFF.md`.
3. Review the staged diff (`git diff --cached`) for secrets, tokens, credentials, usernames,
   emails, private paths, and unrelated changes.
4. Commit.
5. Verify (confirm `git status` is clean and the commit contains only the intended files).
6. Start a fresh Claude Code session in this repo and confirm the SessionStart
   `additionalContext` line appears with accurate prerequisite status (hook edits are
   picked up by the file watcher per current docs, but a fresh session is the clean way to
   double-check).
7. Exit Claude Code.
8. Push `main` to `origin` from the regular terminal, to maintain this repo's established
   manual-push workflow.
