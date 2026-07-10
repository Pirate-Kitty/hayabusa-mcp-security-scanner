import asyncio
import hashlib
import json
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
