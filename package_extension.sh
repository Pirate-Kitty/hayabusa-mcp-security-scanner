#!/usr/bin/env bash
#
# Builds a distributable Claude Desktop extension bundle for hayabusa-mcp.
#
# Vendors this project's Python dependencies into ./lib/ (required because the
# extension's manifest.json points PYTHONPATH at ${__dirname}/lib rather than
# relying on any external virtualenv), then zips manifest.json, server.py, and
# lib/ into dist/hayabusa-mcp.zip.
#
# lib/ is regenerated fresh every run and is not tracked in git: it contains
# compiled, platform-specific wheels (e.g. cryptography, pydantic_core, pyyaml,
# rpds) tied to the machine/Python build that installs them.
#
# The Hayabusa binary itself (./hayabusa/) is intentionally NOT bundled here —
# run download_hayabusa.sh separately; see README.md for extension install steps.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DIST_DIR="./dist"
BUNDLE_NAME="hayabusa-mcp.zip"

for cmd in pip3 zip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found" >&2
        exit 1
    fi
done

echo "Vendoring dependencies into ./lib/ ..."
rm -rf lib
pip3 install --target=lib -r requirements.txt

echo "Packaging extension bundle..."
mkdir -p "$DIST_DIR"
rm -f "${DIST_DIR}/${BUNDLE_NAME}"
zip -rq "${DIST_DIR}/${BUNDLE_NAME}" manifest.json server.py lib/ -x '*__pycache__*'

echo "Done. Extension bundle: ${DIST_DIR}/${BUNDLE_NAME}"
echo "Note: still requires ./hayabusa/ populated separately via download_hayabusa.sh before the extension can run."
