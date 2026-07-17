# hayabusa-mcp

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa)
for EVTX (Windows Event Log) analysis, exposing `scan_evtx`, `get_hayabusa_rules`,
`analyze_coverage`, and `suggest_rule` tools, plus read-only `detection://` resources
for browsing the bundled Sigma rule set (see [Resources](#resources) below).

## Setup

1. `./download_hayabusa.sh` — downloads and checksum-verifies the Hayabusa binary into `./hayabusa/`
2. `pip install -r requirements.txt` (or use a `.venv`)
3. Connect via `.mcp.json` (Claude Code) or as a Claude Desktop extension (see below)

## Tools

- **`scan_evtx`** — runs Hayabusa against an EVTX file and returns findings as
  structured JSON, filterable by severity level.
- **`get_hayabusa_rules`** — lists/searches the bundled Hayabusa and Sigma
  detection rules by keyword.
- **`analyze_coverage`** — given a batch of MITRE ATT&CK technique IDs, reports
  binary local coverage (`covered`/`not_covered`) against the bundled rule set.
- **`suggest_rule`** — given one MITRE ATT&CK technique ID, returns existing
  matching rules if already covered, or a read-only draft rule template
  (never written to disk) if not.

A project-scoped skill at `.claude/skills/detection-engineering/` packages the
rule-authoring workflow built on these tools — see that directory for details.

## Testing

Each test file is run directly (no pytest), the same convention used by the
hooks' own test suite (see [Testing hooks](#testing-hooks) below):

```
.venv/bin/python test_scan_evtx.py
.venv/bin/python test_get_hayabusa_rules.py
.venv/bin/python test_resources.py
.venv/bin/python test_analyze_coverage.py
.venv/bin/python test_suggest_rule.py
```

## Slash commands

- **`/investigate-evtx <evtx-path> [severity]`** — scans an EVTX file,
  resolves findings to MITRE ATT&CK tags, and writes a general
  investigation note under `investigations/` (gitignored), cross-linking
  prior investigations on verified technique/RuleID overlap.
- **`/triage <evtx-path> [severity] [case-id]`** — the case-oriented
  counterpart: same scan → resolve-tags → coverage pipeline, plus a
  required triage outcome (`escalate`, `investigate`, `investigate
  further`, `likely benign`, `insufficient evidence`), writing to
  `investigations/triage/` (gitignored) and syncing reusable
  `techniques/<TechniqueID>.md` knowledge-base notes (tracked in git,
  case-data-free by design).

See `.claude/commands/investigate-evtx.md` and `.claude/commands/triage.md`
for the full step-by-step each command follows.

## Hooks

Four Claude Code hooks live under `.claude/hooks/` and are registered in
`.claude/settings.json`:

- **SessionStart** — read-only prerequisite check (Hayabusa binary present
  and executable, `pyyaml` importable, `hayabusa-mcp` enabled), surfaced as
  context at the start of a session.
- **PreToolUse** (`Write`/`Edit`) — denies writes to sensitive paths:
  repo-internal/vendored directories (`.git/`, `hayabusa/`, `lib/`), the
  hook config itself (`.claude/settings*.json`), credential directories
  (`.ssh/`, `.aws/`, `.gnupg/`), credential/secret/key-shaped files
  (`.env` and variants, `id_rsa` and friends, `credentials`/
  `credentials.json`, `.npmrc`, `.netrc`, and `.pem`/`.key`/`.pfx`/`.p12`/
  `.crt`/`.cer`), or anything resolving outside the project root. Directory
  rules match at any depth, not just directly under the project root;
  matching is case-insensitive.
- **PostToolUse** (`Write`/`Edit`) — after a Sigma/Hayabusa rule YAML is
  written or edited, re-runs the same validator the
  `detection-engineering` skill uses (`validate_rule.py`) and reports any
  structural errors back to Claude.
- **Stop** — fires when Claude finishes responding and sends a fixed,
  generic desktop notification (`notify-send`, if installed) reading
  "Task complete - review required". The notification text is always a
  literal, never built from hook input (no prompt, transcript, file path,
  or session data is ever passed to `notify-send`); the only state written
  is a single timestamp in the OS temp dir, named by a hash of the project
  path rather than the raw path, used solely to debounce repeat
  notifications within 20 seconds. Never blocks the stop and never alters
  Claude's turn — exit code is always 0, with no `decision`/`continue`
  output.

None of these hooks can auto-approve a tool call — manual approval is
unchanged for every file change and command except the narrow sensitive-path
denylist above, which is a hard deny, not an auto-allow. To disable all
hooks locally without touching the shared config, set
`"disableAllHooks": true` in a personal, gitignored
`.claude/settings.local.json`.

### Prerequisites

- Python 3 with `pyyaml` installed — already a project dependency (see
  [Setup](#setup) above); `validate_rule_hook.py` and `session_start_check.py`
  both import it.
- A populated `.venv/` at `.venv/bin/python`. `.claude/settings.json` invokes
  every hook as `${CLAUDE_PROJECT_DIR}/.venv/bin/python ...`, so if that
  interpreter doesn't exist the hook command itself fails to launch (see
  [Troubleshooting](#troubleshooting) below).
- Nothing hook-specific requires `hayabusa/` to be downloaded — a missing or
  non-executable Hayabusa binary is reported by `SessionStart` as a status
  line, not treated as an error.
- `notify-send` is optional, used only by `Stop`. If it isn't installed
  (checked via `shutil.which`), the hook exits 0 with no notification and no
  error — desktop notifications are a convenience, never a dependency.

### Hook setup

No separate installation step: all four hooks are plain Python scripts under
`.claude/hooks/`, already registered in the git-tracked
`.claude/settings.json`. Completing this project's normal [Setup](#setup)
(download Hayabusa, `pip install -r requirements.txt` into `.venv/`) is
enough — Claude Code reads the `hooks` key automatically for any session
started in this project directory, with no extra step to enable any of
them.

### Testing hooks

Run the hook test suite directly (no pytest, same convention as every other
test in this repo):

```
.venv/bin/python .claude/hooks/tests/test_hooks.py
```

This drives each hook's pure logic (`classify()`, `should_skip()`/
`looks_like_rule()`, the `session_start_check` functions, and
`stop_notify`'s `should_notify()`/`state_file_path()`/`read_last_notified()`/
`write_last_notified()`) directly rather than through stdin/stdout, matching
how `test_scan_evtx.py` and the other repo-root suites are run.

### Restarting after a hook change

Claude Code's file watcher normally picks up edits to `.claude/settings.json`
and the hook scripts mid-session. If a change doesn't seem to take effect,
start a fresh Claude Code session in this directory to force a clean
reload — the same operational caveat this project already documents for
`server.py` changes and the MCP connection (see `HANDOFF.md`).

### Troubleshooting

- **A hook doesn't seem to fire at all:** confirm the interpreter exists
  (`ls .venv/bin/python`) — a missing `.venv` makes the hook command fail
  silently rather than raise a visible error. Re-run
  `pip install -r requirements.txt` into `.venv/` if needed.
- **`protect_sensitive_paths.py` blocks a file you expected to write:**
  read the denial reason shown — it names the specific rule that matched
  (a protected directory, a credential file name/extension, or "outside
  the project root"). Treat an unexpected match as a denylist bug to fix,
  not something to work around by disabling hooks project-wide.
- **`validate_rule_hook.py` doesn't flag an invalid rule you just wrote:**
  it only validates files inside the project root, outside `hayabusa/` and
  any `tests/fixtures/` path, that look Sigma/Hayabusa-rule-shaped (a
  `logsource` or `detection` key present) — a file lacking both keys looks
  like "not a rule" to the heuristic and is silently skipped.
- **Need to disable a hook temporarily:** set `"disableAllHooks": true` in
  a personal `.claude/settings.local.json` (gitignored, machine-local)
  rather than editing the shared `.claude/settings.json`.

### Limitations

- `protect_sensitive_paths.py` only covers `Write`/`Edit`. A `Bash` command
  that mutates a sensitive path (`rm`, `mv`, shell redirection) isn't
  covered by this hook — Claude Code's own manual approval for `Bash` still
  applies regardless, so this is a defense-in-depth gap, not a missing
  safeguard.
- `validate_rule_hook.py`'s "does this look like a rule" check (a
  `logsource` or `detection` key) is a heuristic, not a guarantee — it
  could in principle miss an unusual rule dialect or flag an unrelated
  YAML file that happens to define one of those keys.
- Hooks are local automation, not a substitute for reviewing a diff
  yourself before committing — see `HANDOFF.md` for the full
  known-limitations list and this project's standing sensitive-data-sweep
  practice.

## Resources

Alongside the tools above, the server exposes four read-only `detection://` MCP
resources for browsing the bundled Sigma/Hayabusa rule set and looking up
MITRE ATT&CK technique coverage:

- **`detection://rules`** — a compact JSON index of the bundled rules
  (`resource_id`, `id_source`, `title`, `level` only — not full rule bodies).
  Capped at 500 entries per read; `truncated`/`total_rules` in the response
  indicate when more exist.
- **`detection://rules/{rule_identifier}`** — the complete YAML text of one
  rule. `rule_identifier` is the rule's own YAML `id:` (a UUID); a small
  number of rules missing a valid `id` get a stable `fallback-<hash>`
  identifier instead — check `id_source` in the index to tell them apart.
- **`detection://rules/by-technique/{technique_id}`** — rules tagged with a
  given MITRE ATT&CK technique ID (case-insensitive). A bare parent ID like
  `T1003` matches its own tag plus any sub-technique tagged beneath it
  (labeled `inherited_subtechnique` in the response); a specific
  sub-technique query like `T1003.001` matches only that exact tag, never
  its parent or sibling sub-techniques.
- **`detection://attack/techniques/{technique_id}`** — local coverage facts
  for a technique ID (match count, `covered`/`not_covered`), computed solely
  from the bundled rule set. **This server does not bundle an ATT&CK
  technique-name/tactic/description dataset**, so no such fields are
  returned — the response only contains what can be derived from local rule
  data.

## Claude Desktop extension

The extension's `manifest.json` points `PYTHONPATH` at a vendored `./lib/`
directory rather than any external virtualenv. `lib/` is not tracked in git
(it contains compiled, platform-specific wheels) — build it locally with:

```
./package_extension.sh
```

This regenerates `./lib/` from `requirements.txt` and produces
`dist/hayabusa-mcp.zip`. You'll still need `./hayabusa/` populated separately
via `download_hayabusa.sh` before the extension can run.

## License

This project is licensed under the [MIT License](LICENSE).

Hayabusa itself is a separate project licensed under
[AGPL-3.0](https://github.com/Yamato-Security/hayabusa/blob/main/LICENSE.txt).
It is downloaded at setup time by `download_hayabusa.sh` and invoked as an
external subprocess — it is not vendored or linked into this repository.
