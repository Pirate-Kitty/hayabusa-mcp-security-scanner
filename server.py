import asyncio
import json
import tempfile
from pathlib import Path

import anyio
import mcp.types as types
import yaml
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

server = Server("hayabusa-mcp")

HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
HAYABUSA_BIN = HAYABUSA_DIR / "hayabusa-3.10.0-lin-x64-gnu"
RULES_DIR = HAYABUSA_DIR / "rules"
RULE_SUBDIRS = ("hayabusa", "sigma")

_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


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
