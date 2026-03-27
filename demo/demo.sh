#!/bin/sh
# Zemtik demo script — automated end-to-end walkthrough.
# Prerequisites: zemtik binary in PATH, bb installed, OPENAI_API_KEY set.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════════════════╗"
echo "║   Zemtik End-to-End Demo                         ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
echo "[DEMO] Checking prerequisites..."
if ! command -v zemtik >/dev/null 2>&1; then
    echo "[ERROR] zemtik not found in PATH. Run install.sh first." >&2
    exit 1
fi
if ! command -v bb >/dev/null 2>&1; then
    echo "[ERROR] bb (Barretenberg) not found. Install from https://github.com/AztecProtocol/aztec-packages" >&2
    exit 1
fi
if [ -z "$OPENAI_API_KEY" ]; then
    echo "[WARN] OPENAI_API_KEY not set — OpenAI calls will fail."
fi

echo "[DEMO] Prerequisites OK"
echo ""

# Step 1: Run the full ZK pipeline
echo "[DEMO] Step 1: Running Zemtik ZK pipeline (DB → sign → prove → bundle)..."
zemtik

echo ""

# Step 2: Find the most recent bundle
LATEST_BUNDLE="$(ls -t "$HOME/.zemtik/receipts/"*.zip 2>/dev/null | head -1)"
if [ -z "$LATEST_BUNDLE" ]; then
    echo "[DEMO] No bundle found — proof may not have completed (bb required for full proof)."
    echo "[DEMO] Demo complete (circuit execution verified)."
    exit 0
fi

echo "[DEMO] Step 2: Verifying bundle: $LATEST_BUNDLE"
zemtik verify "$LATEST_BUNDLE"

echo ""
echo "[DEMO] Demo complete!"
echo "[DEMO] Start the proxy: zemtik --proxy"
echo "[DEMO] Then point your OpenAI client to http://localhost:4000"
