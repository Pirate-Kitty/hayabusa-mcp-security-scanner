"""Minimal local test for the hayabusa-mcp server's analyze_coverage tool.

Runs the existing server.py implementation against the real Hayabusa rules
bundled in ./hayabusa/rules/, going through the actual registered MCP request
handlers (not the bare undecorated functions), matching the convention used
by test_get_hayabusa_rules.py and test_resources.py.
"""

import asyncio
import json

import mcp.types as types
import server

# Known covered technique (see test_resources.py's SUBTECHNIQUE_RULE_ID / coverage tests).
COVERED_TECHNIQUE_ID = "T1003.001"
COVERED_TECHNIQUE_EXPECTED_COUNT = 123

# Syntactically valid technique ID with zero matching rules in the bundled set.
GAP_TECHNIQUE_ID = "T1003.007"

# Parent technique — direct + inherited sub-technique matches.
PARENT_TECHNIQUE_ID = "T1558"

MALFORMED_TECHNIQUE_ID = "not-a-technique"


async def test_list_tools_exposes_analyze_coverage():
    handler = server.server.request_handlers[types.ListToolsRequest]
    request = types.ListToolsRequest(method="tools/list")
    result = await handler(request)

    tools = result.root.tools
    names = [t.name for t in tools]
    assert "analyze_coverage" in names, f"analyze_coverage not in tool list: {names}"

    tool = next(t for t in tools if t.name == "analyze_coverage")
    props = tool.inputSchema["properties"]
    assert "technique_ids" in props
    assert tool.inputSchema["required"] == ["technique_ids"]
    print("PASS: list_tools_exposes_analyze_coverage")


async def _analyze(**arguments) -> dict:
    handler = server.server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(
            name="analyze_coverage",
            arguments=arguments,
        ),
    )
    result = await handler(request)
    call_result = result.root
    assert isinstance(call_result, types.CallToolResult)
    assert not call_result.isError, call_result.content
    text = "".join(b.text for b in call_result.content if isinstance(b, types.TextContent))
    return json.loads(text)


async def test_single_covered_technique():
    payload = await _analyze(technique_ids=[COVERED_TECHNIQUE_ID])
    assert payload["requested"] == 1
    assert payload["covered"] == 1
    assert payload["not_covered"] == 0

    entry = payload["results"][0]
    assert entry["technique_id"] == COVERED_TECHNIQUE_ID
    assert entry["coverage"] == "covered"
    assert entry["matching_rule_count"] == COVERED_TECHNIQUE_EXPECTED_COUNT
    print(f"PASS: single_covered_technique ({entry['matching_rule_count']} matches)")


async def test_single_gap_technique():
    payload = await _analyze(technique_ids=[GAP_TECHNIQUE_ID])
    entry = payload["results"][0]
    assert entry["coverage"] == "not_covered"
    assert entry["matching_rule_count"] == 0
    assert entry["sample_rule_ids"] == []
    print("PASS: single_gap_technique")


async def test_batch_mixed_covered_and_gap():
    payload = await _analyze(technique_ids=[COVERED_TECHNIQUE_ID, GAP_TECHNIQUE_ID, PARENT_TECHNIQUE_ID])
    assert payload["requested"] == 3
    assert payload["covered"] == 2
    assert payload["not_covered"] == 1

    by_id = {r["technique_id"]: r for r in payload["results"]}
    assert by_id[GAP_TECHNIQUE_ID]["coverage"] == "not_covered"
    assert by_id[PARENT_TECHNIQUE_ID]["coverage"] == "covered"
    print("PASS: batch_mixed_covered_and_gap")


async def test_malformed_id_reported_per_entry_not_raised():
    payload = await _analyze(technique_ids=[COVERED_TECHNIQUE_ID, MALFORMED_TECHNIQUE_ID])
    assert payload["requested"] == 2
    by_id = {r["technique_id"]: r for r in payload["results"]}
    assert "error" in by_id[MALFORMED_TECHNIQUE_ID]
    assert by_id[COVERED_TECHNIQUE_ID]["coverage"] == "covered", (
        "a malformed ID in the batch must not prevent other IDs from resolving"
    )
    print("PASS: malformed_id_reported_per_entry_not_raised")


async def test_coverage_is_binary_and_has_no_attack_metadata():
    payload = await _analyze(technique_ids=[COVERED_TECHNIQUE_ID])
    entry = payload["results"][0]

    assert entry["coverage"] in {"covered", "not_covered"}, (
        f"coverage must be binary, got {entry['coverage']!r}"
    )
    forbidden = {"technique_name", "tactic", "description", "score", "confidence", "quality"}
    assert forbidden.isdisjoint(entry.keys()), f"unexpected metadata/quality fields: {entry.keys()}"
    assert forbidden.isdisjoint(payload.keys()), f"unexpected metadata/quality fields: {payload.keys()}"
    assert "note" in payload
    print("PASS: coverage_is_binary_and_has_no_attack_metadata")


async def main():
    await test_list_tools_exposes_analyze_coverage()
    await test_single_covered_technique()
    await test_single_gap_technique()
    await test_batch_mixed_covered_and_gap()
    await test_malformed_id_reported_per_entry_not_raised()
    await test_coverage_is_binary_and_has_no_attack_metadata()
    print("\nAll tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
