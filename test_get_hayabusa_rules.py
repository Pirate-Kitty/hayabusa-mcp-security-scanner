"""Minimal local test for the hayabusa-mcp server's get_hayabusa_rules tool.

Runs the existing server.py implementation against the real Hayabusa rules
bundled in ./hayabusa/rules/, going through the actual registered MCP request
handlers (not the bare undecorated functions).
"""

import asyncio
import json

import mcp.types as types
import server

KNOWN_RULE_TITLE = "Possible Hidden Shellcode"
KNOWN_RULE_KEYWORD = "hidden shellcode"


async def test_list_tools_exposes_get_hayabusa_rules():
    handler = server.server.request_handlers[types.ListToolsRequest]
    request = types.ListToolsRequest(method="tools/list")
    result = await handler(request)

    tools = result.root.tools
    names = [t.name for t in tools]
    assert "get_hayabusa_rules" in names, f"get_hayabusa_rules not in tool list: {names}"

    tool = next(t for t in tools if t.name == "get_hayabusa_rules")
    props = tool.inputSchema["properties"]
    assert "keyword" in props
    print("PASS: list_tools_exposes_get_hayabusa_rules")


async def _get_rules(**arguments) -> list[dict]:
    handler = server.server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(
            name="get_hayabusa_rules",
            arguments=arguments,
        ),
    )
    result = await handler(request)
    call_result = result.root
    assert isinstance(call_result, types.CallToolResult)
    assert not call_result.isError, call_result.content
    text = "".join(b.text for b in call_result.content if isinstance(b, types.TextContent))
    return json.loads(text)


async def test_call_get_hayabusa_rules_no_keyword_returns_many_rules():
    rules = await _get_rules()
    assert isinstance(rules, list)
    assert len(rules) > 1000, f"expected many bundled rules, got {len(rules)}"
    assert {"id", "title", "level", "path"} <= rules[0].keys()
    print(f"PASS: call_get_hayabusa_rules_no_keyword_returns_many_rules ({len(rules)} rules)")


async def test_keyword_matches_and_excludes():
    matching = await _get_rules(keyword=KNOWN_RULE_KEYWORD)
    assert any(r.get("title") == KNOWN_RULE_TITLE for r in matching), (
        f"expected keyword {KNOWN_RULE_KEYWORD!r} to match {KNOWN_RULE_TITLE!r}: {matching}"
    )

    non_matching = await _get_rules(keyword="nonexistent-rule-xyz-123")
    assert non_matching == [], f"expected no rules for non-matching keyword: {non_matching}"
    print("PASS: keyword_matches_and_excludes")


async def test_keyword_filter_is_case_insensitive():
    lower = await _get_rules(keyword=KNOWN_RULE_KEYWORD.lower())
    upper = await _get_rules(keyword=KNOWN_RULE_KEYWORD.upper())
    assert lower == upper
    assert any(r.get("title") == KNOWN_RULE_TITLE for r in lower)
    print("PASS: keyword_filter_is_case_insensitive")


async def test_rules_have_expected_fields():
    rules = await _get_rules(keyword=KNOWN_RULE_KEYWORD)
    rule = next(r for r in rules if r.get("title") == KNOWN_RULE_TITLE)
    assert rule["id"] == "442c7996-1154-45bd-b203-c20596e7af81"
    assert rule["level"] == "medium"
    assert rule["status"] == "stable"
    assert rule["author"] == "Zach Mathis"
    assert "attack.persistence" in rule["tags"]
    assert rule["path"].endswith(".yml")
    print("PASS: rules_have_expected_fields")


async def main():
    await test_list_tools_exposes_get_hayabusa_rules()
    await test_call_get_hayabusa_rules_no_keyword_returns_many_rules()
    await test_keyword_matches_and_excludes()
    await test_keyword_filter_is_case_insensitive()
    await test_rules_have_expected_fields()
    print("\nAll tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
