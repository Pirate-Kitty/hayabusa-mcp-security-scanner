---
name: detection-engineering
description: Workflow for authoring, validating, and checking MITRE ATT&CK coverage of Hayabusa/Sigma detection rules in this repo. Use when the user asks to write a Sigma rule, write a Hayabusa detection rule, check MITRE ATT&CK technique coverage, draft a new EVTX detection, or validate a rule's YAML before adding it to the rule set.
---

# Detection engineering for hayabusa-mcp

This skill packages the detection-authoring workflow this project already supports through
its MCP tools. It does not reimplement any matching or scanning logic — it wraps the
existing `hayabusa-mcp` tools and adds a local pre-flight validator.

## Workflow

1. **Check existing coverage first.** Before drafting a new rule, call `analyze_coverage`
   (batch) or `suggest_rule` (single technique) with the target MITRE technique ID(s). If a
   technique is already `covered`, review the returned existing rules before writing a new
   one — avoid duplicate/overlapping detections. `suggest_rule` on an uncovered technique
   returns a draft template with `TODO` placeholders; never treat that template as
   finished, and never claim it was written to disk (it isn't).

2. **Fill in the template using the schema reference.** See `reference/rule-schema.md` for
   the required fields and `reference/example-rule.yml` for a complete, valid example. Pay
   particular attention to:
   - `id` must be a real UUID (generate a fresh one — the template's `<generate-a-new-uuid>`
     placeholder is not valid YAML content to leave in).
   - `detection.condition` must reference the selection/filter block(s) you define.
   - MITRE tags use the exact form `attack.tXXXX` or `attack.tXXXX.XXX` (lowercase) — this
     is what `analyze_coverage`/`suggest_rule`/the `by-technique` resource all match on.

3. **Validate locally before relying on a live scan.** Run:
   ```
   python .claude/skills/detection-engineering/scripts/validate_rule.py <path-to-rule.yml>
   ```
   This is a structural/schema check only (required fields, UUID format, condition
   references a defined block) — it cannot tell you whether the rule actually detects
   anything.

4. **Confirm the rule fires.** Use `scan_evtx` against a real EVTX file (or the bundled
   `samples/` fixture, for a sanity check of the tool chain — it only contains a low-severity
   logon-failure event, so it won't exercise most rule logic) to confirm the rule behaves as
   expected. `scan_evtx` reads directly from the rules directory Hayabusa is configured
   against — a drafted rule must actually be placed there to be picked up by a scan; this
   skill and its validator never write to that directory themselves.

5. **Re-check coverage** with `analyze_coverage` after adding the rule, to confirm it now
   reports `covered` for the target technique.

See `reference/mcp-tools.md` for the full tool/resource list this workflow relies on.

## Known limitations to surface, not paper over

- Coverage reported by `analyze_coverage`/`suggest_rule`/the `by-technique` resource is
  **binary only** — `covered` does not mean the rule is well-tuned, low-noise, or enabled
  in every scan profile.
- **No MITRE ATT&CK technique-name/tactic dataset is bundled in this repo.** Technique IDs
  are syntax-validated only (`Tnnnn(.nnn)`); nothing here can resolve a technique's name or
  tactic, or confirm the ID is real. Do not invent one — ask the user for it, or leave it
  out, exactly as `suggest_rule`'s own template does.
- `validate_rule.py` checks structure only, not detection logic correctness or false-positive
  risk.
