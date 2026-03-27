#!/bin/sh
# Zemtik installer — POSIX shell, no sudo required.
# Usage: sh install.sh [--binary-dir <dir>]
# Installs the zemtik binary to ~/.local/bin (or the provided dir),
# creates ~/.zemtik structure, and adds the binary dir to PATH in the
# relevant shell rc file.

set -e

BINARY_DIR="${BINARY_DIR:-$HOME/.local/bin}"
ZEMTIK_HOME="$HOME/.zemtik"

# Allow override via argument
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary-dir) BINARY_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

echo "╔══════════════════════════════════════════════════╗"
echo "║   Zemtik Installer                               ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"
echo "[INSTALL] Platform: $OS / $ARCH"

# Create ~/.zemtik directory structure
echo "[INSTALL] Creating ~/.zemtik directory structure..."
mkdir -p "$ZEMTIK_HOME/circuit"
mkdir -p "$ZEMTIK_HOME/runs"
mkdir -p "$ZEMTIK_HOME/keys"
mkdir -p "$ZEMTIK_HOME/receipts"
mkdir -p "$ZEMTIK_HOME/.tmp"

# Copy circuit source and vendor dependency (required for nargo)
if [ -d "$SCRIPT_DIR/circuit" ]; then
    echo "[INSTALL] Copying circuit files to $ZEMTIK_HOME/circuit/..."
    cp -r "$SCRIPT_DIR/circuit/." "$ZEMTIK_HOME/circuit/"
fi
if [ -d "$SCRIPT_DIR/vendor" ]; then
    echo "[INSTALL] Copying vendor dependencies to $ZEMTIK_HOME/vendor/..."
    mkdir -p "$ZEMTIK_HOME/vendor"
    cp -r "$SCRIPT_DIR/vendor/." "$ZEMTIK_HOME/vendor/"
fi

# Install binary
echo "[INSTALL] Installing zemtik binary to $BINARY_DIR..."
mkdir -p "$BINARY_DIR"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/target/release/zemtik" ]; then
    cp "$SCRIPT_DIR/target/release/zemtik" "$BINARY_DIR/zemtik"
    chmod +x "$BINARY_DIR/zemtik"
    echo "[INSTALL] Copied release binary to $BINARY_DIR/zemtik"
else
    echo "[INSTALL] No release binary found at target/release/zemtik"
    echo "[INSTALL] Build with: cargo build --release"
    echo "[INSTALL] Then re-run this installer."
    exit 1
fi

# Generate default config if not present
CONFIG_FILE="$ZEMTIK_HOME/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[INSTALL] Creating default config at $CONFIG_FILE..."
    cp "$SCRIPT_DIR/config.example.yaml" "$CONFIG_FILE"
fi

# Update PATH in the relevant shell rc file
update_path() {
    RC_FILE="$1"
    PATH_LINE="export PATH=\"\$PATH:$BINARY_DIR\""
    if [ -f "$RC_FILE" ] && grep -q "$BINARY_DIR" "$RC_FILE" 2>/dev/null; then
        echo "[INSTALL] PATH already configured in $RC_FILE"
        return
    fi
    echo "" >> "$RC_FILE"
    echo "# Added by Zemtik installer" >> "$RC_FILE"
    echo "$PATH_LINE" >> "$RC_FILE"
    echo "[INSTALL] Added $BINARY_DIR to PATH in $RC_FILE"
}

case "$SHELL" in
    */zsh)  update_path "$HOME/.zshrc" ;;
    */bash) update_path "$HOME/.bashrc" ;;
    */fish) echo "[INSTALL] Fish shell detected — add $BINARY_DIR to fish path manually" ;;
    *)      update_path "$HOME/.profile" ;;
esac

# Verify installation
export PATH="$PATH:$BINARY_DIR"
if zemtik --version 2>/dev/null; then
    echo ""
    echo "[INSTALL] Installation complete!"
else
    echo ""
    echo "[INSTALL] Binary installed. Restart your shell or run:"
    echo "  export PATH=\"\$PATH:$BINARY_DIR\""
fi

echo ""
echo "  Next steps:"
echo "  1. Set OPENAI_API_KEY in your environment or ~/.zemtik/config.yaml"
echo "  2. Run: zemtik --proxy"
echo "  3. Point your app to http://localhost:4000"
echo ""
