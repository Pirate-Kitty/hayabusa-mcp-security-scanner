#!/usr/bin/env bash
#
# Downloads the official Hayabusa release (pinned version, linux x86_64/gnu build)
# from Yamato-Security/hayabusa, verifies its SHA-256 checksum, and extracts it
# into ./hayabusa/.
#
# Checksum note: Hayabusa releases do not ship dedicated .sha256/.sig files.
# The digest below is the SHA-256 GitHub computed over the uploaded asset bytes
# (exposed via the GitHub Releases API "digest" field), pinned here for
# reproducibility and tamper/corruption detection.

set -euo pipefail

VERSION="3.10.0"
ASSET="hayabusa-${VERSION}-lin-x64-gnu.zip"
URL="https://github.com/Yamato-Security/hayabusa/releases/download/v${VERSION}/${ASSET}"
EXPECTED_SHA256="5879131758c142b0d30d14e4b3f4019155507384d22ad1ce55868670325a071c"
DEST_DIR="./hayabusa"

for cmd in curl sha256sum unzip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found" >&2
        exit 1
    fi
done

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ASSET} (v${VERSION})..."
curl -fsSL -o "${TMPDIR}/${ASSET}" "$URL"

echo "Verifying SHA-256 checksum..."
echo "${EXPECTED_SHA256}  ${TMPDIR}/${ASSET}" | sha256sum -c -

echo "Extracting into ${DEST_DIR}..."
mkdir -p "$DEST_DIR"
unzip -o "${TMPDIR}/${ASSET}" -d "$DEST_DIR"

chmod +x "${DEST_DIR}"/hayabusa-* 2>/dev/null || true

echo "Done. Hayabusa v${VERSION} extracted into ${DEST_DIR}/"
