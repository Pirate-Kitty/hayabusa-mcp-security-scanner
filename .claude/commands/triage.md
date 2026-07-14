---
description: Triage an EVTX file with Hayabusa, map findings to MITRE ATT&CK techniques and Rule IDs, assign a single triage outcome, and write a case note under investigations/triage/, cross-linking related notes on verified overlap only.
argument-hint: <evtx-path> [severity] [case-id]
allowed-tools: Read, Write, Glob, ReadMcpResourceTool, mcp__hayabusa-mcp__scan_evtx, mcp__hayabusa-mcp__get_hayabusa_rules, mcp__hayabusa-mcp__analyze_coverage, mcp__hayabusa-mcp__suggest_rule
---

Triage the EVTX file at `$1` and write an Obsidian-compatible triage note under `investigations/triage/`, syncing reusable ATT&CK technique notes under `techniques/`.

## 1. Parse arguments

- `evtx_path` = `$1`. If empty, stop immediately and report: `Usage: /triage <evtx-path> [severity] [case-id]`. Make no tool calls.
- `severity_arg` = `$2` (may be absent).
- `case_id_arg` = `$3` (may be absent).

## 2. Resolve and validate severity BEFORE scanning

- If `severity_arg` is present: trim whitespace and lowercase it, then check it is exactly one of `informational`, `low`, `medium`, `high`, `critical`.
  - No match → stop immediately, before calling any scan tool, and report: `Invalid severity '<severity_arg>'. Must be exactly one of: informational, low, medium, high, critical.`
  - Match → use the normalized value as `min_severity`.
- If `severity_arg` is absent → `min_severity = "medium"` (the default).

## 3. Validate case_id BEFORE scanning

- If `case_id_arg` is absent, `case_id = null` and this step is done.
- If present: trim whitespace, then check the result matches exactly `^[A-Za-z0-9_-]{1,64}$`.
  - No match (this covers path separators `/` `\`, traversal sequences `..`, shell metacharacters `; | & $ ` " ' * ? ( ) < > ~`, whitespace, email addresses, or any other character outside letters/digits/hyphen/underscore) → stop immediately, before calling any scan tool, and report: `Invalid case ID '<case_id_arg>'. Use only letters, numbers, hyphens, and underscores (max 64 characters).` Do **not** attempt to strip or sanitize the value and continue — reject and stop.
  - Match → use the trimmed value as `case_id`.

## 4. Scan

Call `mcp__hayabusa-mcp__scan_evtx` with `evtx_path`, the resolved `min_severity`, and `output_format="full"`.

- If the tool raises a file-not-found or Hayabusa-binary error, surface that error message verbatim, and add a note that `evtx_path` is resolved by the MCP server against its own process working directory (the repo root) — relative paths should be given relative to the repo root, or as absolute paths.
- If the scan succeeds with **zero findings**, this is not a failure: continue through the remaining steps to write a minimal note with `triage_outcome: insufficient evidence`, and suggest re-running with a lower severity value.

## 5. Resolve MITRE ATT&CK tags per finding

`scan_evtx` findings do **not** carry ATT&CK tags directly — only a `RuleID`. For each **unique** `RuleID` across the findings:

- Read the MCP resource `detection://rules/{RuleID}` via `ReadMcpResourceTool` to get that rule's full YAML text.
- Parse the YAML `tags:` list. Keep only entries matching `^attack\.t\d{4}(\.\d{3})?$` (case-insensitive), and normalize each to `Txxxx` or `Txxxx.xxx` form.
- If the rule has no tags matching that pattern (a real, expected case — not an error), record "no ATT&CK tags for this rule" for that `RuleID`. Never invent or guess a technique ID.
- If the resource lookup fails for a given `RuleID`, record "could not resolve tags for RuleID `<id>`" and continue with the rest.

## 6. Coverage analysis

Union all resolved technique IDs across all rules (dedupe, sort).

- If the union is **non-empty**, call `mcp__hayabusa-mcp__analyze_coverage` with `technique_ids` set to that list.
- If the union is **empty**, do **not** call `analyze_coverage` (its schema requires at least one technique ID — an empty list is a tool error, not a no-op). State plainly that no ATT&CK-tagged rules matched any finding in this scan.

## 7. Priority Findings

Group findings by `Level`, ordered `critical` > `high` > `medium` > `low` > `informational`. Within each group, list: timestamp, rule title, `Computer`, RuleID, and resolved technique tag(s) if any. This is a presentation grouping over the existing `Level` field — there is no separate numeric priority score to compute.

## 8. Assign exactly one triage outcome

Apply this checklist top-down; the **first** rule that matches decides the outcome. Write exactly one outcome plus a one-line justification naming the specific rule, technique, or count that drove the call (and, for a close call, the alternative you considered).

- **escalate**: any `critical` finding; OR any `high` finding whose technique(s) resolve as `covered` in the coverage analysis; OR multiple distinct high-severity techniques observed on the same `Computer`.
- **investigate**: `high`/`medium` findings with technique tags cleanly resolved, no apparent benign explanation, but not meeting the `escalate` bar above.
- **investigate further**: technique tags resolved but `not_covered`; OR a tag-resolution/resource-lookup failure on a finding that would otherwise matter; OR genuinely torn between two outcomes. This is the conservative default when the signal is ambiguous rather than absent.
- **likely benign**: all findings are `low`/`informational`, and no ATT&CK tags resolved for any of them.
- **insufficient evidence**: zero findings at the given severity threshold; OR every finding suffers a tag-resolution failure. Reserved for a lack of data, not a lack of confidence in interpreting the data that exists (that case is `investigate further`).

## 9. Coverage gaps — do not over-reach

Do not automatically call `mcp__hayabusa-mcp__suggest_rule` for every `not_covered` technique. Instead, list `not_covered` techniques in Analyst Notes with a pointer: "run `suggest_rule <technique_id>` (or the `detection-engineering` skill) to draft a rule for this gap." Only call `suggest_rule` directly if the user's invocation explicitly asked for suggestions, and if so, cap it to a small number of techniques.

## 10. Cross-reference related notes — verified overlap only

- `Glob("investigations/*.md")` — existing `/investigate-evtx` notes. (This glob's non-recursive `*` must not match files under `investigations/triage/`.)
- `Glob("investigations/triage/*.md")` — other triage notes.
- `Glob("techniques/*.md")` — technique notes; match by exact `technique_id` frontmatter value.

For each candidate file, parse its YAML frontmatter (`techniques:`/`rule_ids:` lists, or `technique_id:` for technique notes) and compute overlap against this run's resolved technique IDs and RuleIDs. **Only** link a file where there is a verified, exact overlap (case-insensitive exact match — never fuzzy or title-based) on at least one technique ID or RuleID. Files with no verified overlap are not mentioned. This cross-referencing populates the `## Related Notes` section of the triage note only (see step 13) — technique notes never link back to specific investigations (see step 14 and Part 2 of the design).

## 11. Determine the output filename

- No `case_id`: `investigations/triage/<YYYY-MM-DD>-<evtx-basename-without-extension>.md`.
- With `case_id`: `investigations/triage/<case_id>-<YYYY-MM-DD>-<evtx-basename-without-extension>.md`.
- Before writing, check for a collision via `Glob`. If the candidate already exists, try `-2`, `-3`, ... (first free integer suffix) rather than overwriting an existing note.
- Report the exact filename used (and note if a collision occurred) in your final response to the user.

## 12. Write the triage note

`investigations/triage/` is already covered by this repo's existing `.gitignore` entry for `investigations/` (that rule ignores the whole subtree recursively) — no `.gitignore` check or warning is needed for this path, and you must not edit `.gitignore`.

Write the file with this exact frontmatter schema (stable — other tooling may depend on these field names):

```yaml
---
title: "Triage: <evtx-basename>[ (<case_id>)]"
date: <YYYY-MM-DD>
case_id: <case_id, or omit this field entirely if none was given>
source_evtx: <evtx_path as given>
severity_threshold: <resolved min_severity>
triage_outcome: <escalate|investigate|investigate further|likely benign|insufficient evidence>
techniques: [<Txxxx or Txxxx.xxx, ...>]
rule_ids: [<RuleID uuid, ...>]
tags: [hayabusa, triage]
---
```

Followed by these sections, in order:

- `## Summary` — what was scanned, at what severity, how many findings, how many distinct techniques were implicated.
- `## Triage Outcome` — the chosen outcome in bold, the one-line justification from step 8, and any alternative considered.
- `## Priority Findings` — the grouped list from step 7.
- `## Detection Coverage` — the `analyze_coverage` results per technique, or the explicit "no ATT&CK-tagged rules matched" note from step 6.
- `## Analyst Notes` — any interpretation, prefixed `_(auto-drafted, verify before relying on this)_`, plus `not_covered` techniques with the `suggest_rule` pointer from step 9.
- `## Related Notes` — three subsections, `### Related Triage Notes`, `### Related Investigations`, `### Related Techniques`, each populated with the verified-overlap bullets from step 10 (`- [[<filename-without-.md>]] — shares <technique ID(s)/RuleID(s)>` for notes, `- [[Txxxx]]` for techniques) or "None found" if empty.

## 13. Sync technique notes

For every technique ID resolved in step 5, create or update `techniques/<TechniqueID>.md` using this algorithm:

- `Glob("techniques/<TechniqueID>.md")`.
- **Not found** → create the file with this frontmatter and body:

```yaml
---
technique_id: <Txxxx or Txxxx.xxx>
technique_name: "TODO - fill in manually (no bundled ATT&CK name/tactic dataset)"
tactic: "TODO - fill in manually (no bundled ATT&CK name/tactic dataset)"
coverage_status: <covered|not_covered, from analyze_coverage / detection://attack/techniques/{id}>
linked_investigations_count: 1
tags: [attack-technique]
---
```
  ```markdown
  ## Related Rules
  <list from detection://rules/by-technique/{id}: resource_id, title, level — nothing else>

  ## Coverage Status
  <coverage + matching_rule_count from analyze_coverage / detection://attack/techniques/{id}>

  ## Linked Investigations
  Referenced by 1 local triage/investigation run. Details are not tracked in git (see gitignored investigations/).

  ## Analyst Notes
  _(placeholder — add reusable, non-case-specific detection guidance for this technique here)_
  ```

- **Found** → `Read` the whole file as raw text. Locate the four `## <Heading>` lines above by exact match; each section's range runs from its heading to the line before the next recognized heading or end of file.
  - Replace only the `## Related Rules` and `## Coverage Status` ranges with freshly computed content (same sources as above).
  - Increment `linked_investigations_count` in the frontmatter by 1, and rewrite the `## Linked Investigations` sentence to the new count. Do not add any filename, date, case ID, or wikilink to a specific investigation — an aggregate count only.
  - Leave the frontmatter's `technique_name`/`tactic` fields and the entire `## Analyst Notes` section byte-for-byte unchanged from what was read.
  - `Write` the reconstructed file.

**Hard rule, no exceptions:** content written to any `techniques/*.md` file must be sourced only from `get_hayabusa_rules`, `detection://rules/by-technique/{id}`, `analyze_coverage`, and `detection://attack/techniques/{id}`. Never copy a `scan_evtx` finding field (`Computer`, `Timestamp`, `Details`, `ExtraFieldInfo`, `EventID`, `RecordID`, or any observed raw value) into a `techniques/` file — that directory is tracked in git and reusable across cases, and must never contain hostnames, usernames, timestamps, raw event data, private paths, credentials, secrets, or other case-specific or sensitive detail.

Note in your final response to the user which `techniques/*.md` files were created vs. updated.
