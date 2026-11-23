#!/usr/bin/env bash
set -euo pipefail

REPO="Khoinguyen002/ssh-fleet"

OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "$OS_RAW" in
  Linux*)  OS="linux" ;;
  Darwin*) OS="darwin" ;;
  *)
    echo "Unsupported OS: $OS_RAW" >&2
    exit 1
    ;;
esac

case "$ARCH_RAW" in
  x86_64|amd64)   ARCH="amd64" ;;
  arm64|aarch64)  ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH_RAW" >&2
    exit 1
    ;;
esac

ASSET="sf-${OS}-${ARCH}"
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

if [ "$(id -u)" -eq 0 ] || [ -w "/usr/local/bin" ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

TARGET="${INSTALL_DIR}/sf"
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

echo "Downloading ${ASSET} from ${URL}..."
curl -fsSL "$URL" -o "$TMP_FILE"
chmod +x "$TMP_FILE"
mv "$TMP_FILE" "$TARGET"

echo "Installed sf -> ${TARGET}"
if ! command -v sf >/dev/null 2>&1; then
  export PATH="${INSTALL_DIR}:${PATH}"
  echo "Note: add '${INSTALL_DIR}' to your PATH (e.g. export PATH=\"${INSTALL_DIR}:\$PATH\")."
fi

MODE="${1:-}"
if [ -z "$MODE" ]; then
  echo ""
  echo "Next:"
  echo "  - Setup Hub on a public VPS:  sf hub --install-service"
  echo "  - Join a device to Hub:       sf join <HUB_URL> <TOKEN> [--name DEVICE_NAME]"
  exit 0
fi

shift
case "$MODE" in
  hub)
    exec "$TARGET" hub --install-service "$@"
    ;;
  join)
    exec "$TARGET" join "$@"
    ;;
  *)
    exec "$TARGET" "$MODE" "$@"
    ;;
esac
