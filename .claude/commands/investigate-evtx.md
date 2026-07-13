---
description: Scan an EVTX file with Hayabusa, map findings to MITRE ATT&CK coverage, and write a dated investigation note under investigations/, cross-linking prior related investigations.
argument-hint: <evtx-path> [severity]
allowed-tools: Read, Write, Glob, ReadMcpResourceTool, mcp__hayabusa-mcp__scan_evtx, mcp__hayabusa-mcp__get_hayabusa_rules, mcp__hayabusa-mcp__analyze_coverage, mcp__hayabusa-mcp__suggest_rule
---

Investigate the EVTX file at `$1` and write an Obsidian-compatible investigation note under `investigations/`.

## 1. Parse arguments

- `evtx_path` = `$1`. If empty, stop immediately and report: `Usage: /investigate-evtx <evtx-path> [severity]`. Make no tool calls.
- `severity_arg` = `$2` (may be absent).

## 2. Resolve and validate severity BEFORE scanning

- If `severity_arg` is present: trim whitespace and lowercase it, then check it is exactly one of `informational`, `low`, `medium`, `high`, `critical`.
  - No match → stop immediately, before calling any scan tool, and report: `Invalid severity '<severity_arg>'. Must be exactly one of: informational, low, medium, high, critical.`
  - Match → use the normalized value as `min_severity`.
- If `severity_arg` is absent → `min_severity = "medium"` (the default).

## 3. Scan

Call `mcp__hayabusa-mcp__scan_evtx` with `evtx_path`, the resolved `min_severity`, and `output_format="full"`.

- If the tool raises a file-not-found or Hayabusa-binary error, surface that error message verbatim, and add a note that `evtx_path` is resolved by the MCP server against its own process working directory (the repo root) — relative paths should be given relative to the repo root, or as absolute paths.
- If the scan succeeds with **zero findings**, this is not a failure: continue to step 7 to write a minimal note recording that the scan ran and found nothing at `min_severity`, and suggest re-running with a lower severity value.

## 4. Resolve MITRE ATT&CK tags per finding

`scan_evtx` findings do **not** carry ATT&CK tags directly — only a `RuleID`. For each **unique** `RuleID` across the findings:

- Read the MCP resource `detection://rules/{RuleID}` via `ReadMcpResourceTool` to get that rule's full YAML text.
- Parse the YAML `tags:` list. Keep only entries matching `^attack\.t\d{4}(\.\d{3})?$` (case-insensitive), and normalize each to `Txxxx` or `Txxxx.xxx` form (e.g. `attack.t1070.001` → `T1070.001`).
- If the rule has no tags matching that pattern (this is a real, expected case — do not treat it as an error), record "no ATT&CK tags for this rule" for that `RuleID`. Never invent or guess a technique ID.
- If the resource lookup fails for a given `RuleID` (e.g. unknown identifier), record "could not resolve tags for RuleID `<id>`" and continue with the rest.

## 5. Coverage analysis

Union all resolved technique IDs across all rules (dedupe, sort).

- If the union is **non-empty**, call `mcp__hayabusa-mcp__analyze_coverage` with `technique_ids` set to that list.
- If the union is **empty**, do **not** call `analyze_coverage` (its schema requires at least one technique ID — an empty list is a tool error, not just a no-op). Instead, state plainly in the Detection Coverage section that no ATT&CK-tagged rules matched any finding in this scan, and that this can reflect real gaps in this repo's bundled rule tagging (a known, documented limitation — not every rule carries `attack.*` tags).

## 6. Coverage gaps — do not over-reach

Do not automatically call `mcp__hayabusa-mcp__suggest_rule` for every `not_covered` technique — that risks many tool calls on a single busy scan, and rule-drafting is the `detection-engineering` skill's job, not this command's. Instead, list any `not_covered` techniques in Analyst Notes with a pointer: "run `suggest_rule <technique_id>` (or the `detection-engineering` skill) to draft a rule for this gap." Only call `suggest_rule` directly if the user's invocation explicitly asked for suggestions, and if so, cap it to a small number of techniques.

## 7. Cross-reference related investigations

- `Glob("investigations/*.md")`. If there are no matches, note in the final document that this is the first investigation on record.
- For each existing file, read it and parse its YAML frontmatter `techniques:` and `rule_ids:` lists.
- Compute overlap between this run's resolved technique IDs / RuleIDs and each existing file's `techniques:` / `rule_ids:` lists.
- **Only** link a file where there is a verified, exact overlap on at least one technique ID or one RuleID (case-insensitive exact match — never a fuzzy or title-based match). For each such file, add a bullet to Related Investigations: `- [[<filename-without-.md>]] — shares <the overlapping technique ID(s) and/or RuleID(s)>`.
- Files with no verified overlap are not mentioned.

## 8. Determine the output filename

- Candidate: `investigations/<YYYY-MM-DD>-<evtx-basename-without-extension>.md`, using today's date and the EVTX file's basename.
- Before writing, check for a collision via `Glob`. If the candidate already exists, try `-2`, `-3`, ... (first free integer suffix) rather than overwriting an existing note — it may hold another analyst's work.
- Report the exact filename used (and note if a collision occurred) in your final response to the user.

## 9. Check `.gitignore`

Before writing the note, `Read(".gitignore")`. If it does not contain an `investigations/` entry, include a prominent warning in your final response: investigation notes may contain real hostnames, usernames, IPs, or process paths pulled from the analyzed EVTX file and should not be committed until `.gitignore` excludes `investigations/`. Do not edit `.gitignore` yourself.

## 10. Write the investigation note

Write the file with this exact frontmatter schema (future runs of this command depend on the `techniques:` and `rule_ids:` field names for cross-referencing in step 7 — keep them stable):

```yaml
---
title: "Investigation: <evtx-basename>"
date: <YYYY-MM-DD>
source_evtx: <evtx_path as given>
severity_threshold: <resolved min_severity>
techniques: [<Txxxx or Txxxx.xxx, ...>]
rule_ids: [<RuleID uuid, ...>]
tags: [hayabusa, evtx-investigation]
---
```

Followed by these sections:

- `## Summary` — a few sentences: what was scanned, at what severity, how many findings, how many distinct techniques were implicated.
- `## Findings` — one entry per finding (or per RuleID group), including timestamp, rule title, level, computer, and the resolved technique tag(s) if any (as `[[T1070.001]]`-style wikilinks).
- `## Detection Coverage` — the `analyze_coverage` results per technique (`covered`/`not_covered`, `matching_rule_count`), or the explicit "skipped, no tags resolved" note from step 5.
- `## Analyst Notes` — any interpretation, plus `not_covered` techniques with the `suggest_rule` pointer from step 6. Prefix any interpretive claim with `_(auto-drafted, verify before relying on this)_`.
- `## Related Investigations` — the verified-overlap bullets from step 7, or "No related investigations found" / "First investigation on record."

Note near the first `[[technique]]` link that these will render as unresolved/orphan links in Obsidian, since this repo does not bundle an ATT&CK technique-name/tactic dataset (a known, documented gap — not a bug in this command).
