"""Minimal local test for the hayabusa-mcp server's scan_evtx tool.

Runs the existing server.py implementation against a real sample EVTX file
in ./samples/, going through the actual registered MCP request handlers
(not the bare undecorated functions).
"""

import asyncio
import json
import os
from pathlib import Path

import mcp.types as types
import server

SAMPLE_EVTX = Path(__file__).parent / "samples" / "CA_4624_4625_LogonType2_LogonProc_chrome.evtx"
SAMPLE_EVTX_RELATIVE = os.path.relpath(SAMPLE_EVTX, Path.cwd())


async def test_sample_file_present():
    assert SAMPLE_EVTX.is_file(), f"sample EVTX not found: {SAMPLE_EVTX}"
    assert SAMPLE_EVTX.stat().st_size > 0, "sample EVTX is empty"
    print("PASS: sample_file_present")


async def test_list_tools_exposes_scan_evtx():
    handler = server.server.request_handlers[types.ListToolsRequest]
    request = types.ListToolsRequest(method="tools/list")
    result = await handler(request)

    tools = result.root.tools
    names = [t.name for t in tools]
    assert "scan_evtx" in names, f"scan_evtx not in tool list: {names}"

    tool = next(t for t in tools if t.name == "scan_evtx")
    props = tool.inputSchema["properties"]
    assert "evtx_path" in props
    assert "min_severity" in props
    assert "rule_filter" in props
    assert "output_format" in props
    assert "max_results" in props
    assert "evtx_path" in tool.inputSchema.get("required", [])
    print("PASS: list_tools_exposes_scan_evtx")


async def test_call_scan_evtx_against_sample():
    handler = server.server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(
            name="scan_evtx",
            arguments={"evtx_path": str(SAMPLE_EVTX), "min_severity": "informational"},
        ),
    )
    result = await handler(request)
    call_result = result.root

    assert isinstance(call_result, types.CallToolResult)
    assert not call_result.isError, call_result.content
    text = "".join(b.text for b in call_result.content if isinstance(b, types.TextContent))
    findings = json.loads(text)
    assert isinstance(findings, list)
    assert len(findings) > 0
    assert all("Level" in f for f in findings)
    print(f"PASS: call_scan_evtx_against_sample ({len(findings)} findings returned)")


async def _scan(evtx_path: str, min_severity: str, **extra) -> list[dict]:
    handler = server.server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(
            name="scan_evtx",
            arguments={"evtx_path": evtx_path, "min_severity": min_severity, **extra},
        ),
    )
    result = await handler(request)
    call_result = result.root
    assert isinstance(call_result, types.CallToolResult)
    assert not call_result.isError, call_result.content
    text = "".join(b.text for b in call_result.content if isinstance(b, types.TextContent))
    return json.loads(text)


async def test_low_finding_present_at_informational_and_low_but_not_above():
    # Regression test: evtx_path is passed relative to the caller's cwd (as an
    # MCP client would), which previously resolved incorrectly because the
    # Hayabusa subprocess ran with a different cwd.
    for evtx_path in (str(SAMPLE_EVTX), SAMPLE_EVTX_RELATIVE):
        for min_severity in ("informational", "low"):
            findings = await _scan(evtx_path, min_severity)
            assert any(f.get("RuleTitle") == "Logon Failure (Wrong Password)" for f in findings), (
                f"expected 'Logon Failure (Wrong Password)' finding at min_severity={min_severity} "
                f"(evtx_path={evtx_path!r}): {findings}"
            )

        for min_severity in ("medium", "high", "critical"):
            findings = await _scan(evtx_path, min_severity)
            assert not any(f.get("RuleTitle") == "Logon Failure (Wrong Password)" for f in findings), (
                f"did not expect 'Logon Failure (Wrong Password)' finding at min_severity={min_severity} "
                f"(evtx_path={evtx_path!r}): {findings}"
            )
    print("PASS: low_finding_present_at_informational_and_low_but_not_above")


async def test_rule_filter_matches_and_excludes():
    matching = await _scan(str(SAMPLE_EVTX), "informational", rule_filter="wrong password")
    assert any(f.get("RuleTitle") == "Logon Failure (Wrong Password)" for f in matching), (
        f"expected rule_filter to match 'Logon Failure (Wrong Password)': {matching}"
    )

    non_matching = await _scan(str(SAMPLE_EVTX), "informational", rule_filter="nonexistent-rule-xyz")
    assert non_matching == [], f"expected no findings for non-matching rule_filter: {non_matching}"
    print("PASS: rule_filter_matches_and_excludes")


async def test_output_format_summary_vs_full():
    full = await _scan(str(SAMPLE_EVTX), "informational", output_format="full")
    assert len(full) > 0
    assert any("Details" in f for f in full), f"expected 'full' findings to include Details: {full}"

    summary = await _scan(str(SAMPLE_EVTX), "informational", output_format="summary")
    assert len(summary) == len(full)
    assert all("Details" not in f and "ExtraFieldInfo" not in f for f in summary), (
        f"expected 'summary' findings to omit Details/ExtraFieldInfo: {summary}"
    )
    assert all(f.get("RuleTitle") == "Logon Failure (Wrong Password)" for f in summary)
    print("PASS: output_format_summary_vs_full")


async def test_max_results_limits_findings():
    findings = await _scan(str(SAMPLE_EVTX), "informational", max_results=1)
    assert len(findings) <= 1, f"expected at most 1 finding: {findings}"

    unlimited = await _scan(str(SAMPLE_EVTX), "informational")
    assert len(unlimited) >= len(findings)
    print("PASS: max_results_limits_findings")


async def main():
    await test_sample_file_present()
    await test_list_tools_exposes_scan_evtx()
    await test_call_scan_evtx_against_sample()
    await test_low_finding_present_at_informational_and_low_but_not_above()
    await test_rule_filter_matches_and_excludes()
    await test_output_format_summary_vs_full()
    await test_max_results_limits_findings()
    print("\nAll tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
