#!/usr/bin/env bash
# Seed a DEPLOYED Verawall server (e.g. Render) with demo data.
#
# The tenant HMAC key is stored encrypted at rest and can't be read back, so
# this mints a FRESH key with the operator CLI, captures its plaintext in a
# shell variable (never written to disk), and uses it to sign the seed run.
# You supply three secrets at the prompts; nothing is persisted or echoed.
#
# Usage:  ./seed-remote.sh https://your-server.onrender.com
set -euo pipefail

BASE="${1:-}"
if [ -z "$BASE" ]; then echo "usage: ./seed-remote.sh <server-url>"; exit 1; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
GO_DIR="$HERE/fraud-ingest-server-go"
SIM_DIR="$HERE/fraud-ingest-server"

read -rs -p "Render MASTER_KEY:            " MASTER_KEY; echo
read -rs -p "Render EXTERNAL DATABASE_URL: " DBURL;      echo
read -rs -p "Render CONSOLE_KEY:           " CONSOLE_KEY; echo
export MASTER_KEY CONSOLE_KEY

echo "→ building operator CLI …"
( cd "$GO_DIR" && go build -o vera-go . )

echo "→ minting a fresh tenant key (captured in memory only) …"
OUT="$( cd "$GO_DIR" && DATABASE_URL="$DBURL" ./vera-go tenant rotate-key wallet-acme )"
SDK_KEY="$(printf '%s\n' "$OUT" | sed -n 's/.*key=\([0-9a-f][0-9a-f]*\).*/\1/p')"
KEY_ID="$(printf '%s\n' "$OUT"  | sed -n 's/.*kid=\([^ ]*\) key=.*/\1/p')"
if [ -z "$SDK_KEY" ]; then echo "!! could not parse a key from rotate-key output"; echo "$OUT"; exit 1; fi
export SDK_KEY KEY_ID
echo "  minted kid=$KEY_ID (key length ${#SDK_KEY})"

echo "→ waiting for the server's key cache to refresh (~6s) …"
sleep 6

echo "→ seeding $BASE …"
( cd "$SIM_DIR" && node simulate-sdk.js seed "$BASE" )

unset MASTER_KEY CONSOLE_KEY SDK_KEY KEY_ID DBURL
echo "✓ done — secrets cleared from this shell."
