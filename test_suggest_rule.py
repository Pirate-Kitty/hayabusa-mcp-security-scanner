"""Minimal local test for the hayabusa-mcp server's suggest_rule tool.

Runs the existing server.py implementation against the real Hayabusa rules
bundled in ./hayabusa/rules/, going through the actual registered MCP request
handlers (not the bare undecorated functions), matching the convention used
by test_analyze_coverage.py and test_resources.py.
"""

import asyncio
import json
import os

import mcp.types as types
import server

RULES_DIR = server.RULES_DIR

# Known covered technique (see test_resources.py / test_analyze_coverage.py).
COVERED_TECHNIQUE_ID = "T1003.001"

# Syntactically valid technique ID with zero matching rules in the bundled set.
GAP_TECHNIQUE_ID = "T1003.007"

MALFORMED_TECHNIQUE_ID = "not-a-technique"


async def test_list_tools_exposes_suggest_rule():
    handler = server.server.request_handlers[types.ListToolsRequest]
    request = types.ListToolsRequest(method="tools/list")
    result = await handler(request)

    tools = result.root.tools
    names = [t.name for t in tools]
    assert "suggest_rule" in names, f"suggest_rule not in tool list: {names}"

    tool = next(t for t in tools if t.name == "suggest_rule")
    props = tool.inputSchema["properties"]
    assert "technique_id" in props
    assert "title" in props
    assert tool.inputSchema["required"] == ["technique_id"]
    print("PASS: list_tools_exposes_suggest_rule")


async def _suggest(**arguments):
    handler = server.server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(
            name="suggest_rule",
            arguments=arguments,
        ),
    )
    result = await handler(request)
    return result.root


async def _suggest_ok(**arguments) -> dict:
    call_result = await _suggest(**arguments)
    assert isinstance(call_result, types.CallToolResult)
    assert not call_result.isError, call_result.content
    text = "".join(b.text for b in call_result.content if isinstance(b, types.TextContent))
    return json.loads(text)


async def test_covered_technique_returns_existing_rules_no_template():
    payload = await _suggest_ok(technique_id=COVERED_TECHNIQUE_ID)
    assert payload["technique_id"] == COVERED_TECHNIQUE_ID
    assert payload["coverage"] == "covered"
    assert payload["matching_rule_count"] > 0
    assert payload["existing_rules"], "expected existing_rules to be populated for a covered technique"
    assert payload["rule_template"] is None, "a covered technique must not also suggest a new template"
    print("PASS: covered_technique_returns_existing_rules_no_template")


async def test_gap_technique_returns_template_with_only_technique_tag():
    payload = await _suggest_ok(technique_id=GAP_TECHNIQUE_ID)
    assert payload["technique_id"] == GAP_TECHNIQUE_ID
    assert payload["coverage"] == "not_covered"
    assert payload["matching_rule_count"] == 0
    assert payload["existing_rules"] == []

    template = payload["rule_template"]
    assert template is not None
    assert template["tags"] == [f"attack.{GAP_TECHNIQUE_ID.lower()}"], (
        "template must not invent any tag beyond the literal technique ID"
    )
    print("PASS: gap_technique_returns_template_with_only_technique_tag")


async def test_custom_title_seeds_template():
    payload = await _suggest_ok(technique_id=GAP_TECHNIQUE_ID, title="My Custom Rule Title")
    assert payload["rule_template"]["title"] == "My Custom Rule Title"
    print("PASS: custom_title_seeds_template")


async def test_malformed_technique_id_is_error_result():
    call_result = await _suggest(technique_id=MALFORMED_TECHNIQUE_ID)
    assert isinstance(call_result, types.CallToolResult)
    assert call_result.isError, "malformed technique ID must surface as an error CallToolResult"
    print("PASS: malformed_technique_id_is_error_result")


async def test_no_attack_metadata_invented():
    covered_payload = await _suggest_ok(technique_id=COVERED_TECHNIQUE_ID)
    gap_payload = await _suggest_ok(technique_id=GAP_TECHNIQUE_ID)

    forbidden = {"technique_name", "tactic", "tactic_id", "confidence", "quality"}
    for payload in (covered_payload, gap_payload):
        assert forbidden.isdisjoint(payload.keys()), f"unexpected metadata fields: {payload.keys()}"
        for rule in payload["existing_rules"]:
            assert forbidden.isdisjoint(rule.keys()), f"unexpected metadata fields: {rule.keys()}"
        if payload["rule_template"] is not None:
            assert forbidden.isdisjoint(payload["rule_template"].keys())
    print("PASS: no_attack_metadata_invented")


async def test_reuses_coverage_logic_matches_analyze_coverage():
    suggest_handler = server.server.request_handlers[types.CallToolRequest]

    async def call(tool_name, **arguments):
        request = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name=tool_name, arguments=arguments),
        )
        result = await suggest_handler(request)
        call_result = result.root
        assert not call_result.isError, call_result.content
        text = "".join(b.text for b in call_result.content if isinstance(b, types.TextContent))
        return json.loads(text)

    suggest_payload = await call("suggest_rule", technique_id=COVERED_TECHNIQUE_ID)
    coverage_payload = await call("analyze_coverage", technique_ids=[COVERED_TECHNIQUE_ID])

    assert suggest_payload["matching_rule_count"] == coverage_payload["results"][0]["matching_rule_count"], (
        "suggest_rule and analyze_coverage must agree — both are backed by _matches_for_technique()"
    )
    print("PASS: reuses_coverage_logic_matches_analyze_coverage")


async def test_read_only_no_rule_files_created_or_modified():
    before = {
        str(p): p.stat().st_mtime_ns
        for p in RULES_DIR.rglob("*.yml")
    }

    await _suggest_ok(technique_id=GAP_TECHNIQUE_ID, title="Should Not Touch Disk")
    await _suggest_ok(technique_id=COVERED_TECHNIQUE_ID)

    after = {
        str(p): p.stat().st_mtime_ns
        for p in RULES_DIR.rglob("*.yml")
    }
    assert before == after, "suggest_rule must never create or modify any rule file on disk"
    print("PASS: read_only_no_rule_files_created_or_modified")


async def main():
    await test_list_tools_exposes_suggest_rule()
    await test_covered_technique_returns_existing_rules_no_template()
    await test_gap_technique_returns_template_with_only_technique_tag()
    await test_custom_title_seeds_template()
    await test_malformed_technique_id_is_error_result()
    await test_no_attack_metadata_invented()
    await test_reuses_coverage_logic_matches_analyze_coverage()
    await test_read_only_no_rule_files_created_or_modified()
    print("\nAll tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
