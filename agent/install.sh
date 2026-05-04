#!/bin/sh
set -e

SERVER_URL="${ITOM_SERVER_URL:-http://localhost:3005}"
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
BINARY_NAME="itom-agent"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux)  OS="linux" ;;
  darwin) OS="darwin" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

FILENAME="${BINARY_NAME}-${OS}-${ARCH}"
DOWNLOAD_URL="${SERVER_URL}/v1/agents/download/${FILENAME}"
DEST="${INSTALL_DIR}/${BINARY_NAME}"

echo "Detected: ${OS}/${ARCH}"
echo "Downloading ${FILENAME} from ${SERVER_URL}..."

curl -fsSL "$DOWNLOAD_URL" -o "$DEST"
chmod +x "$DEST"

# Remove macOS quarantine attribute — Gatekeeper blocks binaries downloaded
# via browser but not via curl. Strip it explicitly as a safety net.
if [ "$OS" = "darwin" ]; then
  xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
fi

echo "Installed to $DEST"
echo ""
echo "Run with:"
echo "  ITOM_SERVER_URL=${SERVER_URL} ${DEST}"
