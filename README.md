# hayabusa-mcp

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa)
for EVTX (Windows Event Log) analysis, exposing `scan_evtx` and `get_hayabusa_rules`
tools, plus read-only `detection://` resources for browsing the bundled Sigma
rule set (see [Resources](#resources) below).

> **Note:** this README covers licensing and the Claude Desktop extension build
> step. Full setup/usage documentation is still in progress — see `HANDOFF.md`
> for detailed background in the meantime.

## Setup

1. `./download_hayabusa.sh` — downloads and checksum-verifies the Hayabusa binary into `./hayabusa/`
2. `pip install -r requirements.txt` (or use a `.venv`)
3. Connect via `.mcp.json` (Claude Code) or as a Claude Desktop extension (see below)

## Resources

Alongside the two tools, the server exposes four read-only `detection://` MCP
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
