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
