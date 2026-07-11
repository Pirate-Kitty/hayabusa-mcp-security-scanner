# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This project is an MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis.

## Goals

- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files, returning structured JSON, filterable by severity level, with graceful error handling
- Expose a `get_hayabusa_rules` tool to list/search the bundled Hayabusa and Sigma detection rules
- Expose `analyze_coverage` and `suggest_rule` tools for MITRE ATT&CK technique coverage checks and read-only rule-drafting guidance
- Expose read-only `detection://` MCP resources for browsing the bundled rule set and technique coverage (see README.md for the full list)

## Stack

- Python, using the `mcp` library
- Hayabusa CLI, installed locally (invoked as a subprocess)
- PyYAML for parsing the bundled detection rules

## Skills

- `.claude/skills/detection-engineering/` — project-scoped skill for authoring, validating, and checking MITRE ATT&CK coverage of detection rules using the tools above. Use it when asked to write, validate, or check coverage for a Sigma/Hayabusa rule.
