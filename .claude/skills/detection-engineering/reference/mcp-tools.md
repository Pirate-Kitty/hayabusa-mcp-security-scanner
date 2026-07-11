# hayabusa-mcp tool &amp; resource reference

The `hayabusa-mcp` MCP server (`server.py` at the repo root) is the source of truth for
rule coverage and scanning — never re-derive matching logic by hand when one of these
already does it. Referenced here by function name, not line number, since line numbers
drift as `server.py` changes.

## Tools

- **`scan_evtx`** (`run_scan()`) — runs the real Hayabusa binary against an EVTX file and
  returns findings as JSON. Params: `evtx_path` (required), `min_severity`, `rule_filter`
  (substring match on `RuleTitle`), `output_format` (`full`/`summary`), `max_results`. Use
  this to confirm a drafted rule actually fires against a real or sample EVTX — a rule
  passing `validate_rule.py` only means it's well-formed, not that it detects anything.

- **`get_hayabusa_rules`** (`list_rules()`) — lists the ~4,960 bundled rules, optionally
  filtered by a case-insensitive `keyword` match against title/description/tags. No
  pagination — broad keyword queries can exceed MCP's output size limit; narrow the
  keyword if that happens.

- **`analyze_coverage`** (`_analyze_coverage()`) — given a batch of MITRE technique IDs,
  returns binary `covered`/`not_covered` per ID plus a matching rule count and sample rule
  IDs. Built on `_matches_for_technique()`, the same helper the `by-technique` resource and
  `suggest_rule` use, so results can't disagree with those.

- **`suggest_rule`** (`_suggest_rule()`) — given one technique ID (+ optional `title`):
  if covered, returns the existing matching rules for review instead of a template; if not
  covered, returns a draft rule skeleton (see `example-rule.yml`'s shape) as **data only —
  nothing is ever written to disk**. The template deliberately leaves `TODO` placeholders
  for `id`, `description`, `logsource.service`, the `selection` fields, and `level` — it
  never invents an ATT&CK technique name or tactic, because none is bundled in this repo.

## Resources (`detection://`)

- **`detection://rules`** — compact JSON index (`resource_id`, `id_source`, `title`,
  `level`), capped at 500 rows with `truncated`/`total_rules` flags.
- **`detection://rules/{rule_identifier}`** — full YAML text of one rule, byte-faithful.
  `rule_identifier` is the rule's own `id:` UUID (or a `fallback-<hash>` if missing).
- **`detection://rules/by-technique/{technique_id}`** — rules tagged with a technique,
  including `match_type` (`direct` vs `inherited_subtechnique`).
- **`detection://attack/techniques/{technique_id}`** — local coverage facts only
  (`covered`/`not_covered`, match count) — no technique name/tactic, by design.

## Known, documented product gaps

- Coverage is strictly **binary**. `covered` says nothing about detection quality, tuning,
  false-positive rate, or whether the rule is enabled in a given scan profile.
- **No ATT&CK technique-name/tactic dataset is bundled anywhere in this repo.** Technique
  IDs are validated only for `Tnnnn(.nnn)` syntax — nothing here can confirm an ID is a
  real MITRE technique or resolve its name/tactic.

Do not present either gap as fixed or worked around by this skill — surface them to the
user instead.
