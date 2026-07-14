#!/bin/sh

set -eu

METADATA_URL="${CODETRUSS_INSTALL_METADATA_URL:-https://codetruss.com/downloads/codetruss-cli-latest.json}"

if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'CodeTruss requires Node.js 20.9 or newer: https://nodejs.org/' >&2
  exit 1
fi

if ! node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 20 || (major === 20 && minor >= 9) ? 0 : 1)' >/dev/null 2>&1; then
  printf 'CodeTruss requires Node.js 20.9 or newer; found %s.\n' "$(node --version)" >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  printf '%s\n' 'CodeTruss requires npm, which normally ships with Node.js.' >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  printf '%s\n' 'CodeTruss requires curl to download and verify the release artifact.' >&2
  exit 1
fi

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/codetruss-cli.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT HUP INT TERM
ARCHIVE="$SCRATCH/codetruss-cli.tgz"

if [ -n "${CODETRUSS_INSTALL_URL:-}" ]; then
  PACKAGE_URL="$CODETRUSS_INSTALL_URL"
  EXPECTED_SHA256="${CODETRUSS_INSTALL_SHA256:-}"
  if [ -z "$EXPECTED_SHA256" ]; then
    printf '%s\n' 'CODETRUSS_INSTALL_SHA256 is required with a custom CODETRUSS_INSTALL_URL.' >&2
    exit 1
  fi
else
  METADATA="$SCRATCH/release.json"
  curl --fail --silent --show-error --location "$METADATA_URL" --output "$METADATA"
  PACKAGE_URL="$(node -e 'const fs = require("node:fs"); const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(new URL(data.url, process.argv[2]).href)' "$METADATA" "$METADATA_URL")"
  EXPECTED_SHA256="$(node -e 'const fs = require("node:fs"); const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); if (!/^[a-f0-9]{64}$/i.test(data.sha256 || "")) process.exit(1); process.stdout.write(data.sha256.toLowerCase())' "$METADATA")"
fi

printf 'Downloading CodeTruss CLI from %s\n' "$PACKAGE_URL"
curl --fail --silent --show-error --location "$PACKAGE_URL" --output "$ARCHIVE"
ACTUAL_SHA256="$(node -e 'const fs = require("node:fs"); const crypto = require("node:crypto"); process.stdout.write(crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex"))' "$ARCHIVE")"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  printf 'CodeTruss release checksum mismatch: expected %s, received %s.\n' "$EXPECTED_SHA256" "$ACTUAL_SHA256" >&2
  exit 1
fi

printf 'Checksum verified: %s\n' "$ACTUAL_SHA256"
npm install --global --ignore-scripts --no-audit --no-fund "$ARCHIVE"

PREFIX="${NPM_CONFIG_PREFIX:-$(npm prefix --global)}"
EXECUTABLE="$PREFIX/bin/codetruss"
if [ ! -x "$EXECUTABLE" ]; then
  printf 'CodeTruss installed, but its executable was not found at %s.\n' "$EXECUTABLE" >&2
  exit 1
fi

"$EXECUTABLE" --version
if ! command -v codetruss >/dev/null 2>&1; then
  printf 'Add %s/bin to PATH, then run: codetruss init\n' "$PREFIX"
else
  printf '%s\n' 'Ready. Run: codetruss init'
fi
