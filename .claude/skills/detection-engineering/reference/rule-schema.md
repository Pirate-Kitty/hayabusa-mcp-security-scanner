# Rule schema cheatsheet

Distilled from the rules actually bundled under `hayabusa/rules/{hayabusa,sigma}/` (not
copied from any single file — that directory is gitignored and populated by
`download_hayabusa.sh`, so it may not exist in a fresh clone). This is what
`server.py`'s `list_rules()` and `_matches_for_technique()` actually read, so treat this
file as the contract those functions rely on. See `example-rule.yml` in this same
directory for a complete minimal example.

There are two rule dialects in this repo: plain **Sigma** (`hayabusa/rules/sigma/`) and
**Hayabusa-native** (`hayabusa/rules/hayabusa/`, `ruletype: Hayabusa`, sometimes with an
extra `details:` alert-message template and an embedded `sample-evtx:` block). The fields
below are the common subset both dialects share and that this server depends on.

| Field | Required | Notes |
|---|---|---|
| `title` | yes | Short human-readable name. |
| `id` | yes | A UUID, unique across the rule set. `server.py` uses this verbatim as the rule's `resource_id`; a missing/blank `id` falls back to a `fallback-<hash>` identifier (see `_derive_rule_identifier` in `server.py`). |
| `status` | yes | e.g. `experimental`, `test`, `stable`. |
| `description` | yes | What behavior the rule detects. |
| `logsource` | yes | Dict with at least `product` (e.g. `windows`); often also `service` (e.g. `security`, `sysmon`). |
| `detection` | yes | Dict with one or more `selection*`/`filter*` blocks plus a `condition` string referencing them (e.g. `condition: selection`). |
| `level` | yes | e.g. `informational`, `low`, `medium`, `high`, `critical` — this is what `scan_evtx`'s `min_severity` filters against. |
| `tags` | no, but required for coverage tooling | List of strings. MITRE ATT&CK tags use the form `attack.tXXXX` or `attack.tXXXX.XXX` (lowercase). `analyze_coverage`/`suggest_rule`/`detection://rules/by-technique/{id}` all match against this exact tag format. |
| `author` | no | Free text. |
| `falsepositives` | no | List of known benign triggers. |
| `references` | no | List of URLs. |

## MITRE technique tag matching (`_rule_matches_technique` in `server.py`)

- A tag `attack.t1003` matches a query for the parent technique `T1003` directly.
- A tag `attack.t1003.001` matches a query for the exact sub-technique `T1003.001` directly,
  and also matches a query for the bare parent `T1003` as an `inherited_subtechnique` match.
- A sub-technique query never matches a sibling sub-technique or an unrelated parent.

## What this repo does *not* have

- No bundled ATT&CK technique-name/tactic/description dataset — only the literal
  `Tnnnn(.nnn)` ID is validated (regex syntax check), never resolved to a name.
- No YAML schema file or linter — `validate_rule.py` in `../scripts/` is this skill's own
  lightweight check, not an upstream tool.
