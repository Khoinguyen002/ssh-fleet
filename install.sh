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

EXISTING_BIN="$(command -v sf 2>/dev/null || true)"
if [ -n "$EXISTING_BIN" ] && [ -w "$(dirname "$EXISTING_BIN")" ]; then
  TARGET="$EXISTING_BIN"
  INSTALL_DIR="$(dirname "$TARGET")"
elif [ -x "${HOME}/.local/bin/sf" ]; then
  INSTALL_DIR="${HOME}/.local/bin"
  TARGET="${INSTALL_DIR}/sf"
elif [ "$(id -u)" -eq 0 ] || [ -w "/usr/local/bin" ]; then
  INSTALL_DIR="/usr/local/bin"
  TARGET="${INSTALL_DIR}/sf"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
  TARGET="${INSTALL_DIR}/sf"
fi

TMP_FILE="${TARGET}.tmp.$$"
trap 'rm -f "$TMP_FILE"' EXIT

echo "Downloading ${ASSET} from ${URL}..."
curl -fsSL "$URL" -o "$TMP_FILE"
chmod +x "$TMP_FILE"
mv -f "$TMP_FILE" "$TARGET"

echo "Installed sf -> ${TARGET}"
if ! command -v sf >/dev/null 2>&1; then
  export PATH="${INSTALL_DIR}:${PATH}"
  echo "Note: add '${INSTALL_DIR}' to your PATH (e.g. export PATH=\"${INSTALL_DIR}:\$PATH\")."
fi

restart_active_services() {
  if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
    for unit in ssh-fleet-hub ssh-fleet-agent; do
      if systemctl --user is-active --quiet "$unit" 2>/dev/null; then
        systemctl --user restart "$unit" && echo "Restarted systemd user service: ${unit}"
      fi
      if [ "$(id -u)" -eq 0 ] && systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl restart "$unit" && echo "Restarted systemd service: ${unit}"
      fi
    done
  elif [ "$OS" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
    PLIST="${HOME}/Library/LaunchAgents/com.sshfleet.agent.plist"
    if [ -f "$PLIST" ] && launchctl list 2>/dev/null | grep -q "com.sshfleet.agent"; then
      launchctl kickstart -k "gui/$(id -u)/com.sshfleet.agent" 2>/dev/null || {
        launchctl unload "$PLIST" 2>/dev/null || true
        launchctl load -w "$PLIST"
      }
      echo "Restarted LaunchAgent: com.sshfleet.agent"
    fi
  fi
}

MODE="${1:-}"
if [ -z "$MODE" ]; then
  restart_active_services
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
  update)
    restart_active_services
    ;;
  *)
    exec "$TARGET" "$MODE" "$@"
    ;;
esac
