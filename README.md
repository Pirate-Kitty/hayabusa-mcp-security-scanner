# hayabusa-mcp

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa)
for EVTX (Windows Event Log) analysis, exposing `scan_evtx` and `get_hayabusa_rules`
tools.

> **Note:** this README covers licensing and the Claude Desktop extension build
> step. Full setup/usage documentation is still in progress — see `HANDOFF.md`
> for detailed background in the meantime.

## Setup

1. `./download_hayabusa.sh` — downloads and checksum-verifies the Hayabusa binary into `./hayabusa/`
2. `pip install -r requirements.txt` (or use a `.venv`)
3. Connect via `.mcp.json` (Claude Code) or as a Claude Desktop extension (see below)

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
