"""Minimal local test for the hayabusa-mcp server's detection:// resources.

Runs the existing server.py implementation against the real Hayabusa rules
bundled in ./hayabusa/rules/, going through the actual registered MCP request
handlers (not the bare undecorated functions), matching the convention used
by test_scan_evtx.py and test_get_hayabusa_rules.py.
"""

import asyncio
import json
import warnings

import mcp.types as types
import server

KNOWN_RULE_ID = "442c7996-1154-45bd-b203-c20596e7af81"
KNOWN_RULE_TITLE = "Possible Hidden Shellcode"

# Rule tagged only attack.t1003 (parent, no sub-technique tag).
PARENT_ONLY_RULE_ID = "4973dea2-3985-affa-babc-f0c00821d2a1"
# Rule tagged only attack.t1003.001.
SUBTECHNIQUE_RULE_ID = "5b6e58ee-c231-4a54-9eee-af2577802e08"
# Rule tagged only attack.t1003.002 — a sibling of SUBTECHNIQUE_RULE_ID under the same parent.
SIBLING_SUBTECHNIQUE_RULE_ID = "99522854-7b20-5e8d-3c15-f9df0964b49e"
# Syntactically valid technique ID with no matching rules in the bundled set.
UNMATCHED_TECHNIQUE_ID = "T9999"


async def test_list_resources_exposes_rules_index():
    handler = server.server.request_handlers[types.ListResourcesRequest]
    request = types.ListResourcesRequest(method="resources/list")
    result = await handler(request)

    resources = result.root.resources
    index = next((r for r in resources if str(r.uri) == "detection://rules"), None)
    assert index is not None, f"detection://rules not in resource list: {resources}"
    assert index.mimeType == "application/json"
    print("PASS: list_resources_exposes_rules_index")


async def _read_resource(uri: str):
    handler = server.server.request_handlers[types.ReadResourceRequest]
    request = types.ReadResourceRequest(
        method="resources/read",
        params=types.ReadResourceRequestParams(uri=uri),
    )
    result = await handler(request)
    contents = result.root.contents
    assert len(contents) == 1
    return contents[0]


async def test_read_rules_index_shape_and_compactness():
    content = await _read_resource("detection://rules")
    assert content.mimeType == "application/json"
    payload = json.loads(content.text)

    assert set(payload.keys()) == {"total_rules", "returned", "truncated", "duplicate_ids", "rules"}
    assert payload["total_rules"] > 4900, f"expected many bundled rules, got {payload['total_rules']}"
    assert len(payload["rules"]) <= 500
    assert payload["truncated"] is True
    assert payload["duplicate_ids"] == {}, f"expected no duplicate ids today: {payload['duplicate_ids']}"

    row = payload["rules"][0]
    assert set(row.keys()) == {"resource_id", "id_source", "title", "level"}, (
        f"expected compact row shape, got: {row.keys()}"
    )
    print(f"PASS: read_rules_index_shape_and_compactness ({payload['total_rules']} total rules)")


async def test_unknown_resource_uri_raises():
    try:
        await _read_resource("detection://bogus")
    except ValueError:
        print("PASS: unknown_resource_uri_raises")
        return
    raise AssertionError("expected ValueError for an unrecognized detection:// URI")


async def test_fallback_identifier_is_marked():
    identifier, id_source = server._derive_rule_identifier(None, "some/path.yml")
    assert id_source == "fallback"
    assert identifier.startswith("fallback-")
    assert len(identifier) == len("fallback-") + 16

    identifier_again, _ = server._derive_rule_identifier(None, "some/path.yml")
    assert identifier == identifier_again, "fallback identifiers must be deterministic across calls"

    identifier_yaml, id_source_yaml = server._derive_rule_identifier(KNOWN_RULE_ID, "irrelevant.yml")
    assert id_source_yaml == "yaml"
    assert identifier_yaml == KNOWN_RULE_ID
    print("PASS: fallback_identifier_is_marked")


async def test_duplicate_identifiers_excluded_from_lookup():
    synthetic = [
        {"id": "dup-uuid", "title": "Rule A", "level": "low", "path": "a.yml"},
        {"id": "dup-uuid", "title": "Rule B", "level": "high", "path": "b.yml"},
        {"id": "unique-uuid", "title": "Rule C", "level": "medium", "path": "c.yml"},
    ]

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _, by_id, duplicate_ids = server._build_rule_index(synthetic)

    assert "dup-uuid" not in by_id, "duplicated identifier must not silently resolve to one rule"
    assert "unique-uuid" in by_id
    assert duplicate_ids == {"dup-uuid": ["a.yml", "b.yml"]}
    assert any(issubclass(w.category, RuntimeWarning) for w in caught), "expected a RuntimeWarning"
    print("PASS: duplicate_identifiers_excluded_from_lookup")


async def test_list_resource_templates_exposes_all_three_templates():
    handler = server.server.request_handlers[types.ListResourceTemplatesRequest]
    request = types.ListResourceTemplatesRequest(method="resources/templates/list")
    result = await handler(request)

    uris = {t.uriTemplate for t in result.root.resourceTemplates}
    expected = {
        "detection://rules/{rule_identifier}",
        "detection://rules/by-technique/{technique_id}",
        "detection://attack/techniques/{technique_id}",
    }
    assert expected <= uris, f"missing templates: {expected - uris}"
    print("PASS: list_resource_templates_exposes_all_three_templates")


async def test_read_single_rule_by_identifier_returns_full_yaml():
    import yaml as pyyaml

    content = await _read_resource(f"detection://rules/{KNOWN_RULE_ID}")
    assert content.mimeType == "application/yaml"
    data = pyyaml.safe_load(content.text)
    assert data["id"] == KNOWN_RULE_ID
    assert data["title"] == KNOWN_RULE_TITLE
    print("PASS: read_single_rule_by_identifier_returns_full_yaml")


async def test_read_single_rule_unknown_identifier_raises():
    try:
        await _read_resource("detection://rules/does-not-exist")
    except ValueError:
        print("PASS: read_single_rule_unknown_identifier_raises")
        return
    raise AssertionError("expected ValueError for an unknown rule identifier")


async def test_read_duplicate_identifier_raises():
    original_index, original_by_id, original_dupes = server._RULE_INDEX, server._RULE_INDEX_BY_ID, server._DUPLICATE_RULE_IDS
    synthetic = [
        {"id": "dup-uuid", "title": "Rule A", "level": "low", "path": "a.yml"},
        {"id": "dup-uuid", "title": "Rule B", "level": "high", "path": "b.yml"},
    ]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        server._RULE_INDEX, server._RULE_INDEX_BY_ID, server._DUPLICATE_RULE_IDS = server._build_rule_index(synthetic)
    try:
        try:
            server._read_rule_yaml_by_id("dup-uuid")
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError when reading a duplicated identifier")
    finally:
        server._RULE_INDEX, server._RULE_INDEX_BY_ID, server._DUPLICATE_RULE_IDS = (
            original_index,
            original_by_id,
            original_dupes,
        )
    print("PASS: read_duplicate_identifier_raises")


async def _by_technique(technique_id: str) -> dict:
    content = await _read_resource(f"detection://rules/by-technique/{technique_id}")
    assert content.mimeType == "application/json"
    return json.loads(content.text)


async def _coverage(technique_id: str) -> dict:
    content = await _read_resource(f"detection://attack/techniques/{technique_id}")
    assert content.mimeType == "application/json"
    return json.loads(content.text)


def _resource_ids(payload: dict) -> set:
    return {r["resource_id"] for r in payload["rules"]}


async def test_technique_normalization_case_insensitive():
    lower = await _by_technique("t1003.001")
    upper = await _by_technique("T1003.001")
    assert lower == upper
    assert lower["technique_id"] == "T1003.001"
    print("PASS: technique_normalization_case_insensitive")


async def test_technique_parent_matches_direct_and_subtechnique():
    payload = await _by_technique("T1003")
    by_id = {r["resource_id"]: r for r in payload["rules"]}

    assert PARENT_ONLY_RULE_ID in by_id, "expected parent-only-tagged rule to match T1003"
    assert by_id[PARENT_ONLY_RULE_ID]["match_type"] == "direct"

    assert SUBTECHNIQUE_RULE_ID in by_id, "expected sub-technique-tagged rule to match parent T1003"
    assert by_id[SUBTECHNIQUE_RULE_ID]["match_type"] == "inherited_subtechnique"
    print("PASS: technique_parent_matches_direct_and_subtechnique")


async def test_technique_subtechnique_excludes_parent_and_siblings():
    payload = await _by_technique("T1003.001")
    ids = _resource_ids(payload)

    assert SUBTECHNIQUE_RULE_ID in ids, "expected exact sub-technique match"
    assert PARENT_ONLY_RULE_ID not in ids, "sub-technique query must not match parent-only tag"
    assert SIBLING_SUBTECHNIQUE_RULE_ID not in ids, "sub-technique query must not match a sibling sub-technique"
    print("PASS: technique_subtechnique_excludes_parent_and_siblings")


async def test_technique_malformed_id_raises():
    try:
        await _by_technique("not-a-technique")
    except ValueError:
        print("PASS: technique_malformed_id_raises")
        return
    raise AssertionError("expected ValueError for a malformed technique ID")


async def test_coverage_status_covered():
    payload = await _coverage("T1003.001")
    assert payload["coverage"] == "covered"
    assert payload["matching_rule_count"] > 0
    assert set(payload.keys()) == {
        "technique_id", "coverage", "matching_rule_count", "sample_rule_ids", "note",
    }
    forbidden = {"technique_name", "tactic", "description"}
    assert forbidden.isdisjoint(payload.keys()), f"must not invent ATT&CK metadata: {payload.keys()}"
    print(f"PASS: coverage_status_covered ({payload['matching_rule_count']} matches)")


async def test_coverage_status_not_covered():
    payload = await _coverage(UNMATCHED_TECHNIQUE_ID)
    assert payload["coverage"] == "not_covered"
    assert payload["matching_rule_count"] == 0
    assert payload["sample_rule_ids"] == []
    print("PASS: coverage_status_not_covered")


async def main():
    await test_list_resources_exposes_rules_index()
    await test_read_rules_index_shape_and_compactness()
    await test_unknown_resource_uri_raises()
    await test_fallback_identifier_is_marked()
    await test_duplicate_identifiers_excluded_from_lookup()
    await test_list_resource_templates_exposes_all_three_templates()
    await test_read_single_rule_by_identifier_returns_full_yaml()
    await test_read_single_rule_unknown_identifier_raises()
    await test_read_duplicate_identifier_raises()
    await test_technique_normalization_case_insensitive()
    await test_technique_parent_matches_direct_and_subtechnique()
    await test_technique_subtechnique_excludes_parent_and_siblings()
    await test_technique_malformed_id_raises()
    await test_coverage_status_covered()
    await test_coverage_status_not_covered()
    print("\nAll tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
