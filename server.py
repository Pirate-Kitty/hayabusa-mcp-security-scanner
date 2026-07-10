import asyncio
import hashlib
import json
import re
import tempfile
import warnings
from pathlib import Path

import anyio
import mcp.types as types
import yaml
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server

server = Server("hayabusa-mcp")

HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
HAYABUSA_BIN = HAYABUSA_DIR / "hayabusa-3.10.0-lin-x64-gnu"
RULES_DIR = HAYABUSA_DIR / "rules"
RULE_SUBDIRS = ("hayabusa", "sigma")

_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

_MAX_RESOURCE_ROWS = 500
_COVERAGE_SAMPLE_CAP = 20

_TECHNIQUE_ID_RE = re.compile(r"^[Tt](\d{4})(\.(\d{3}))?$")


SUMMARY_FIELDS = ("Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "RuleID")


def _filter_findings(
    findings: list[dict],
    rule_filter: str | None,
    output_format: str,
    max_results: int | None,
) -> list[dict]:
    if rule_filter:
        needle = rule_filter.lower()
        findings = [f for f in findings if needle in str(f.get("RuleTitle", "")).lower()]

    if max_results is not None:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [{k: f[k] for k in SUMMARY_FIELDS if k in f} for f in findings]

    return findings


async def run_scan(
    evtx_path: str,
    min_severity: str,
    rule_filter: str | None = None,
    output_format: str = "full",
    max_results: int | None = None,
) -> list[dict]:
    evtx_file = Path(evtx_path).resolve()
    if not evtx_file.is_file():
        raise FileNotFoundError(f"EVTX file not found: {evtx_path}")
    if not HAYABUSA_BIN.is_file():
        raise FileNotFoundError(f"Hayabusa binary not found: {HAYABUSA_BIN}")

    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "results.jsonl"
        cmd = [
            str(HAYABUSA_BIN),
            "json-timeline",
            "-f", str(evtx_file),
            "-L",
            "-o", str(output_file),
            "-m", min_severity,
            "-w",
            "-q",
            "-K",
            "-N",
            "-C",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=HAYABUSA_DIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"Hayabusa exited with code {proc.returncode}: "
                f"{stderr.decode(errors='replace').strip()}"
            )

        if not output_file.is_file():
            return []

        findings = []
        with output_file.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
        return _filter_findings(findings, rule_filter, output_format, max_results)


def list_rules(keyword: str | None = None) -> list[dict]:
    if not RULES_DIR.is_dir():
        raise FileNotFoundError(f"Hayabusa rules directory not found: {RULES_DIR}")

    needle = keyword.lower() if keyword else None
    rules = []
    for subdir in RULE_SUBDIRS:
        for path in (RULES_DIR / subdir).rglob("*.yml"):
            with path.open(encoding="utf-8") as f:
                try:
                    data = yaml.load(f, Loader=_YAML_LOADER)
                except yaml.YAMLError:
                    continue
            if not isinstance(data, dict):
                continue

            title = data.get("title", "")
            description = data.get("description", "")
            tags = data.get("tags") or []

            if needle:
                haystack = " ".join(str(v) for v in (title, description, *tags)).lower()
                if needle not in haystack:
                    continue

            rules.append({
                "id": data.get("id"),
                "title": title,
                "description": description,
                "level": data.get("level"),
                "status": data.get("status"),
                "author": data.get("author"),
                "tags": tags,
                "logsource_product": (data.get("logsource") or {}).get("product"),
                "path": str(path.relative_to(RULES_DIR)),
            })

    rules.sort(key=lambda r: str(r["title"]).lower())
    return rules


_RULE_INDEX: list[dict] | None = None
_RULE_INDEX_BY_ID: dict[str, dict] | None = None
_DUPLICATE_RULE_IDS: dict[str, list[str]] | None = None


def _derive_rule_identifier(rule_id, relative_path: str) -> tuple[str, str]:
    """Return (identifier, id_source) for a rule.

    Prefers the rule's own YAML `id:` (a UUID) verbatim. Falls back to a
    deterministic sha256-of-path identifier when `id` is missing/blank, so
    every parsed rule stays addressable. Uses hashlib rather than Python's
    built-in hash(), which is randomized per-process via PYTHONHASHSEED and
    would produce a different identifier on every server restart.
    """
    if isinstance(rule_id, str) and rule_id.strip():
        return rule_id.strip(), "yaml"
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:16]
    return f"fallback-{digest}", "fallback"


def _build_rule_index(records: list[dict]) -> tuple[list[dict], dict[str, dict], dict[str, list[str]]]:
    """Enrich rule records with a stable resource_id/id_source and detect
    identifier collisions. Rules whose derived identifier collides with
    another rule's are excluded from the lookup table entirely (never
    silently resolved to one of them) and reported in duplicate_ids.
    """
    counts: dict[str, int] = {}
    enriched = []
    for record in records:
        identifier, id_source = _derive_rule_identifier(record.get("id"), record["path"])
        row = {**record, "resource_id": identifier, "id_source": id_source}
        enriched.append(row)
        counts[identifier] = counts.get(identifier, 0) + 1

    by_id: dict[str, dict] = {}
    duplicates: dict[str, list[str]] = {}
    for row in enriched:
        identifier = row["resource_id"]
        if counts[identifier] > 1:
            duplicates.setdefault(identifier, []).append(row["path"])
            continue
        by_id[identifier] = row

    for identifier, paths in duplicates.items():
        warnings.warn(
            f"Duplicate rule identifier {identifier!r} found in {len(paths)} rule files "
            f"{paths}; these rules are excluded from detection://rules/{{rule_identifier}} "
            "lookups until the conflict is resolved upstream.",
            RuntimeWarning,
            stacklevel=2,
        )

    return enriched, by_id, duplicates


def _get_rule_index() -> tuple[list[dict], dict[str, dict], dict[str, list[str]]]:
    """Lazily parse and cache the full rule tree once per process lifetime.

    Rules are static for the life of the process; a restart is required to
    pick up changed/added rule files, matching the existing live-reload
    caveat that already applies to code changes in this file.
    """
    global _RULE_INDEX, _RULE_INDEX_BY_ID, _DUPLICATE_RULE_IDS
    if _RULE_INDEX is None:
        _RULE_INDEX, _RULE_INDEX_BY_ID, _DUPLICATE_RULE_IDS = _build_rule_index(list_rules(None))
    return _RULE_INDEX, _RULE_INDEX_BY_ID, _DUPLICATE_RULE_IDS


def _rules_index_payload() -> dict:
    records, _, duplicate_ids = _get_rule_index()
    page = records[:_MAX_RESOURCE_ROWS]
    return {
        "total_rules": len(records),
        "returned": len(page),
        "truncated": len(records) > len(page),
        "duplicate_ids": duplicate_ids,
        "rules": [
            {
                "resource_id": r["resource_id"],
                "id_source": r["id_source"],
                "title": r["title"],
                "level": r["level"],
            }
            for r in page
        ],
    }


def _read_rule_yaml_by_id(rule_id: str) -> str:
    """Return the complete, unparsed YAML text of the rule matching rule_id.

    Deliberately does not re-parse the YAML: the resource's job is to return
    the rule byte-faithfully, not a normalized/parsed view of it.
    """
    _, by_id, duplicate_ids = _get_rule_index()
    if rule_id in duplicate_ids:
        paths = duplicate_ids[rule_id]
        raise ValueError(
            f"Rule identifier {rule_id!r} is ambiguous: it appears in {len(paths)} "
            f"rule files {paths}. This indicates a duplicate id: value upstream and "
            "cannot be resolved to a single rule."
        )
    record = by_id.get(rule_id)
    if record is None:
        raise ValueError(f"Unknown rule identifier: {rule_id!r}")
    return (RULES_DIR / record["path"]).read_text(encoding="utf-8")


def _normalize_technique_id(raw: str) -> tuple[str, bool]:
    """Return (normalized_id, is_subtechnique) for a MITRE technique ID.

    Case-insensitive; accepts a bare parent ("T1003") or a specific
    sub-technique ("T1003.001"). Raises ValueError for anything else.
    """
    match = _TECHNIQUE_ID_RE.match(raw.strip()) if isinstance(raw, str) else None
    if not match:
        raise ValueError(f"Malformed MITRE technique ID: {raw!r}")
    base, sub = match.group(1), match.group(3)
    normalized = f"t{base}" + (f".{sub}" if sub else "")
    return normalized, sub is not None


def _rule_matches_technique(rule_tags: list[str], normalized: str, is_subtechnique: bool) -> str | None:
    """Return "direct", "inherited_subtechnique", or None for a rule's tags
    against a normalized technique ID.

    A sub-technique query ("t1003.001") matches only that exact tag — never
    its parent or sibling sub-techniques. A parent query ("t1003") matches
    its own tag directly, and any more-specific sub-technique tag under it
    as an inherited match, since MITRE defines sub-techniques as refinements
    of the parent.
    """
    target = f"attack.{normalized}"
    if is_subtechnique:
        return "direct" if target in rule_tags else None
    if target in rule_tags:
        return "direct"
    if any(t.startswith(target + ".") for t in rule_tags):
        return "inherited_subtechnique"
    return None


def _matches_for_technique(raw_technique_id: str) -> tuple[str, list[dict]]:
    normalized, is_subtechnique = _normalize_technique_id(raw_technique_id)
    records, _, _ = _get_rule_index()
    matches = []
    for record in records:
        tags = [str(t) for t in (record.get("tags") or [])]
        match_type = _rule_matches_technique(tags, normalized, is_subtechnique)
        if match_type is not None:
            matches.append({**record, "match_type": match_type})
    return normalized.upper(), matches


def _rules_by_technique_payload(raw_technique_id: str) -> dict:
    technique_id, matches = _matches_for_technique(raw_technique_id)
    page = matches[:_MAX_RESOURCE_ROWS]
    return {
        "technique_id": technique_id,
        "total_matches": len(matches),
        "returned": len(page),
        "truncated": len(matches) > len(page),
        "rules": [
            {
                "resource_id": r["resource_id"],
                "id_source": r["id_source"],
                "title": r["title"],
                "level": r["level"],
                "match_type": r["match_type"],
            }
            for r in page
        ],
    }


def _technique_coverage_payload(raw_technique_id: str) -> dict:
    technique_id, matches = _matches_for_technique(raw_technique_id)
    return {
        "technique_id": technique_id,
        "coverage": "covered" if matches else "not_covered",
        "matching_rule_count": len(matches),
        "sample_rule_ids": [r["resource_id"] for r in matches[:_COVERAGE_SAMPLE_CAP]],
        "note": (
            "ID and local rule-coverage facts only. This server does not bundle "
            "an ATT&CK technique-name/tactic/description dataset, so no such "
            "fields are included here — treat the absence of a technique name "
            "as a known product gap, not an omission by mistake."
        ),
    }


def _analyze_coverage(raw_technique_ids: list[str]) -> dict:
    """Binary local-coverage summary for a batch of technique IDs.

    Reuses _matches_for_technique() per ID — no new matching logic, so this
    cannot drift from detection://attack/techniques/{id}. A malformed ID is
    reported per-entry rather than raised, since one bad ID in a batch
    shouldn't fail the whole call the way the single-ID resource does.
    """
    results = []
    covered_count = 0
    for raw_id in raw_technique_ids:
        try:
            technique_id, matches = _matches_for_technique(raw_id)
        except ValueError as exc:
            results.append({"technique_id": raw_id, "error": str(exc)})
            continue
        is_covered = len(matches) > 0
        covered_count += int(is_covered)
        results.append({
            "technique_id": technique_id,
            "coverage": "covered" if is_covered else "not_covered",
            "matching_rule_count": len(matches),
            "sample_rule_ids": [r["resource_id"] for r in matches[:_COVERAGE_SAMPLE_CAP]],
        })
    return {
        "requested": len(raw_technique_ids),
        "covered": covered_count,
        "not_covered": len(raw_technique_ids) - covered_count,
        "results": results,
        "note": (
            "ID and local rule-coverage facts only, per technique. Coverage is "
            "binary (covered/not_covered) and says nothing about detection "
            "quality, tuning, or whether a rule is enabled in a given scan "
            "profile. This server does not bundle an ATT&CK technique-name/"
            "tactic dataset, so no such fields are included here."
        ),
    }


_SUGGEST_RULE_NOTE = (
    "Guidance and/or a draft rule template only — nothing is written to disk. "
    "This server does not bundle an ATT&CK technique-name/tactic dataset, so "
    "no technique name or tactic tag is invented; the template's only ATT&CK "
    "tag is the literal technique ID supplied by the caller. Coverage here is "
    "binary (covered/not_covered) and does not imply detection quality, "
    "tuning, or that any listed rule is enabled in a given scan profile."
)


def _suggest_rule(raw_technique_id: str, title: str | None = None) -> dict:
    """Read-only guidance for improving local coverage of a technique.

    Never creates or modifies rule files — returns a template as data only.
    Reuses _matches_for_technique() for coverage (no separate matching logic
    to drift out of sync with the by-technique resource / analyze_coverage).
    Does not invent an ATT&CK technique name or tactic tag: this server has
    no such dataset, so the only tag suggested is the literal technique ID
    supplied by the caller.
    """
    technique_id, matches = _matches_for_technique(raw_technique_id)
    is_covered = len(matches) > 0

    if is_covered:
        return {
            "technique_id": technique_id,
            "coverage": "covered",
            "matching_rule_count": len(matches),
            "guidance": (
                "Local rules already exist for this technique. Review/tune the "
                "existing rules below before authoring a new one, to avoid "
                "duplicate or overlapping detections."
            ),
            "existing_rules": [
                {"resource_id": r["resource_id"], "title": r["title"], "level": r["level"]}
                for r in matches[:_COVERAGE_SAMPLE_CAP]
            ],
            "rule_template": None,
            "note": _SUGGEST_RULE_NOTE,
        }

    template_title = (
        title.strip() if isinstance(title, str) and title.strip() else f"TODO: {technique_id} Detection"
    )
    rule_template = {
        "title": template_title,
        "id": "<generate-a-new-uuid>",
        "status": "experimental",
        "description": f"TODO: describe the behavior this rule detects for {technique_id}.",
        "logsource": {"product": "windows", "service": "TODO"},
        "detection": {
            "selection": {"TODO_field": "TODO_value"},
            "condition": "selection",
        },
        "level": "TODO",
        "tags": [f"attack.{technique_id.lower()}"],
    }
    return {
        "technique_id": technique_id,
        "coverage": "not_covered",
        "matching_rule_count": 0,
        "guidance": (
            "No local rule currently matches this technique. The template below "
            "is a starting skeleton only — it is not written to disk, and every "
            "TODO field must be filled in and validated before use."
        ),
        "existing_rules": [],
        "rule_template": rule_template,
        "note": _SUGGEST_RULE_NOTE,
    }


def _parse_detection_uri(uri) -> tuple[str, ...]:
    if uri.scheme != "detection":
        raise ValueError(f"Unsupported resource URI scheme: {uri.scheme!r}")
    path = (uri.path or "").strip("/")
    segments = [uri.host or ""] + ([s for s in path.split("/") if s] if path else [])
    return tuple(segments)


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    return [
        types.Resource(
            uri="detection://rules",
            name="Detection rules index",
            description=(
                "Compact JSON index of bundled Hayabusa/Sigma rules "
                "(resource_id, id_source, title, level only — not full rule "
                f"bodies). Capped at {_MAX_RESOURCE_ROWS} entries per read; "
                "see 'truncated'/'total_rules' in the response."
            ),
            mimeType="application/json",
        ),
    ]


@server.list_resource_templates()
async def list_resource_templates() -> list[types.ResourceTemplate]:
    return [
        types.ResourceTemplate(
            uriTemplate="detection://rules/{rule_identifier}",
            name="Single detection rule",
            description=(
                "Full YAML text of one rule, addressed by its own YAML id: "
                "field (UUID), or a fallback-<hash> identifier (see id_source "
                "in detection://rules) for the rare rule missing one."
            ),
            mimeType="application/yaml",
        ),
        types.ResourceTemplate(
            uriTemplate="detection://rules/by-technique/{technique_id}",
            name="Rules by MITRE technique",
            description=(
                "Rules tagged with the given MITRE ATT&CK technique ID "
                "(case-insensitive). A bare parent ID like T1003 also matches "
                "sub-technique-tagged rules like T1003.001 (labeled "
                "'inherited_subtechnique'); a sub-technique query like T1003.001 "
                "matches only that exact tag, never its parent or siblings."
            ),
            mimeType="application/json",
        ),
        types.ResourceTemplate(
            uriTemplate="detection://attack/techniques/{technique_id}",
            name="Local technique coverage",
            description=(
                "Local coverage facts (match count, covered/not_covered) for a "
                "technique ID, computed only from the bundled rule set. Does "
                "not include the technique's name/tactic — no ATT&CK dataset "
                "is bundled in this server."
            ),
            mimeType="application/json",
        ),
    ]


@server.read_resource()
async def read_resource(uri: types.AnyUrl):
    # Note: unlike call_tool (which wraps exceptions into isError=True
    # CallToolResults), the MCP SDK's read_resource wrapper has no
    # try/except — any exception raised here propagates as a JSON-RPC
    # protocol-level error, not a content-block error.
    segments = _parse_detection_uri(uri)

    if segments == ("rules",):
        payload = _rules_index_payload()
        return [ReadResourceContents(content=json.dumps(payload, indent=2), mime_type="application/json")]

    if len(segments) == 2 and segments[0] == "rules":
        text = _read_rule_yaml_by_id(segments[1])
        return [ReadResourceContents(content=text, mime_type="application/yaml")]

    if len(segments) == 3 and segments[:2] == ("rules", "by-technique"):
        payload = _rules_by_technique_payload(segments[2])
        return [ReadResourceContents(content=json.dumps(payload, indent=2), mime_type="application/json")]

    if len(segments) == 3 and segments[:2] == ("attack", "techniques"):
        payload = _technique_coverage_payload(segments[2])
        return [ReadResourceContents(content=json.dumps(payload, indent=2), mime_type="application/json")]

    raise ValueError(f"Unknown resource URI: {uri}")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="scan_evtx",
            description="Scan an EVTX (Windows Event Log) file with Hayabusa and return findings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {
                        "type": "string",
                        "description": "Path to the EVTX file to scan.",
                    },
                    "min_severity": {
                        "type": "string",
                        "description": "Minimum severity level to include in results.",
                        "enum": ["informational", "low", "medium", "high", "critical"],
                    },
                    "rule_filter": {
                        "type": "string",
                        "description": "Case-insensitive substring to match against the rule title. Only matching findings are returned.",
                    },
                    "output_format": {
                        "type": "string",
                        "description": "'full' returns all fields per finding; 'summary' returns only key fields.",
                        "enum": ["summary", "full"],
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of findings to return.",
                        "minimum": 1,
                    },
                },
                "required": ["evtx_path"],
            },
        ),
        types.Tool(
            name="get_hayabusa_rules",
            description="List Hayabusa detection rules, optionally filtered by keyword.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Case-insensitive substring to match against a rule's title, description, or tags. Only matching rules are returned.",
                    },
                },
            },
        ),
        types.Tool(
            name="analyze_coverage",
            description=(
                "Report local rule coverage for one or more MITRE ATT&CK technique IDs. "
                "Coverage is a binary covered/not_covered signal based only on whether the "
                "bundled rule set has a rule tagged with the given technique — it does not "
                "indicate detection quality, tuning, or whether a rule is enabled in a given "
                "scan profile. This server does not bundle an ATT&CK technique-name or "
                "tactic dataset, so no such fields are returned."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "technique_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "description": (
                            "One or more MITRE technique IDs (e.g. 'T1003.001'), case-insensitive. "
                            "A bare parent ID like 'T1003' also counts matches from its "
                            "sub-techniques, same as detection://attack/techniques/{technique_id}."
                        ),
                    },
                },
                "required": ["technique_ids"],
            },
        ),
        types.Tool(
            name="suggest_rule",
            description=(
                "Read-only guidance for a MITRE technique ID: if local rules already "
                "cover it, lists them for review; otherwise returns a draft Sigma-style "
                "rule template skeleton to fill in. Never creates or modifies any rule "
                "file — the template is returned as data only. Does not invent an "
                "ATT&CK technique name or tactic; the only ATT&CK tag used is the "
                "literal technique ID supplied."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "A single MITRE technique ID (e.g. 'T1003.001'), case-insensitive.",
                    },
                    "title": {
                        "type": "string",
                        "description": (
                            "Optional title to seed the draft rule template's 'title' field "
                            "when the technique is not yet covered."
                        ),
                    },
                },
                "required": ["technique_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.ContentBlock]:
    if name == "scan_evtx":
        evtx_path = arguments["evtx_path"]
        min_severity = arguments.get("min_severity", "informational")
        rule_filter = arguments.get("rule_filter")
        output_format = arguments.get("output_format", "full")
        max_results = arguments.get("max_results")
        findings = await run_scan(evtx_path, min_severity, rule_filter, output_format, max_results)
        return [types.TextContent(type="text", text=json.dumps(findings, indent=2))]

    if name == "get_hayabusa_rules":
        keyword = arguments.get("keyword")
        rules = list_rules(keyword)
        return [types.TextContent(type="text", text=json.dumps(rules, indent=2))]

    if name == "analyze_coverage":
        technique_ids = arguments["technique_ids"]
        payload = _analyze_coverage(technique_ids)
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]

    if name == "suggest_rule":
        technique_id = arguments["technique_id"]
        title = arguments.get("title")
        payload = _suggest_rule(technique_id, title)
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]

    raise ValueError(f"Unknown tool: {name}")


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    anyio.run(main)
