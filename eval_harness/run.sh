#!/usr/bin/env bash
# MCP Boss eval harness one-command runner.
#
# Drives every scenario in ./scenarios against a running MCP Boss instance,
# scores the traces, and prints the resulting scorecard.
#
# Env vars:
#   MCP_URL          defaults to http://localhost:8080
#   MCP_ID_TOKEN     optional; required if the target has OAUTH_CLIENT_ID set
#   EVAL_MODEL       defaults to gemini-2.5-flash
#   RESULTS_FILE     defaults to results.json
#   SCORECARD_FILE   defaults to scorecard.md

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

MCP_URL="${MCP_URL:-http://localhost:8080}"
EVAL_MODEL="${EVAL_MODEL:-gemini-2.5-flash}"
RESULTS_FILE="${RESULTS_FILE:-results.json}"
SCORECARD_FILE="${SCORECARD_FILE:-scorecard.md}"

if [[ -z "${MCP_URL}" ]]; then
  echo "ERROR: MCP_URL is not set and no default resolved." >&2
  exit 1
fi

RUNNER_ARGS=(--scenarios scenarios --mcp-url "$MCP_URL" --model "$EVAL_MODEL" --out "$RESULTS_FILE")
if [[ -n "${MCP_ID_TOKEN:-}" ]]; then
  RUNNER_ARGS+=(--token "$MCP_ID_TOKEN")
else
  echo "note: MCP_ID_TOKEN not set; assuming target is running without OAuth."
fi

echo "=== [1/2] running scenarios against $MCP_URL ==="
python3 runner.py "${RUNNER_ARGS[@]}"

echo ""
echo "=== [2/2] scoring $RESULTS_FILE into $SCORECARD_FILE ==="
python3 scoring.py "$RESULTS_FILE" \
  --scenarios scenarios \
  --model "$EVAL_MODEL" \
  --publish "$SCORECARD_FILE"

echo ""
echo "=== scorecard: $SCORECARD_FILE ==="
cat "$SCORECARD_FILE"
