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

- `download_hayabusa.sh` — downloads, checksum-verifies, and extracts Hayabusa into `./hayabusa/`
- `hayabusa/` — extracted Hayabusa v3.10.0 release (binary, `config/`, `rules/`)
- `server.py` — low-level MCP server (`hayabusa-mcp`); registers two tools:
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

Remaining:
1. Push `main` to `origin`
2. Post-push verification — confirm the pushed commits appear correctly on the remote (`git log`/`git diff` against `origin/main` after push), and re-run the live tool/resource checks above against a fresh clone to confirm nothing depended on uncommitted local state

## Next step

The Claude Desktop extension is fully set up and confirmed working end-to-end: both `get_hayabusa_rules` (26 Mimikatz matches) and `scan_evtx` (absolute EVTX path, real findings) have been exercised live from Claude Desktop — see "Claude Desktop extension setup" above, including the Linux unpacked-extension `0600` binary-permission issue and its `chmod 755` workaround.

Publication cleanup is complete: machine-specific paths and username scrubbed from tracked files, `lib/` untracked (regenerated via `package_extension.sh`), sample EVTX provenance documented, `LICENSE` and `README.md` added, and git history replaced with a single sanitized initial commit. The branch has been renamed to `main`, and the working tree is clean.

Remaining:
1. Create the empty GitHub repository and push `main`
2. Write up a Medium article covering the build process
