package keyring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const keyringTimeoutMarkerFilename = "antigravity-keyring-unavailable"

const pythonUnlockScript = `
import sys
from gi.repository import Gio, GLib

pw = sys.stdin.buffer.read()
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)

def get_locked():
    res = bus.call_sync(
        'org.freedesktop.secrets',
        '/org/freedesktop/secrets/collection/login',
        'org.freedesktop.DBus.Properties',
        'Get',
        GLib.Variant('(ss)', ('org.freedesktop.Secret.Collection', 'Locked')),
        GLib.VariantType('(v)'),
        Gio.DBusCallFlags.NONE,
        2000,
        None,
    )
    return bool(res.unpack()[0])

if not get_locked():
    print('UNLOCKED')
    sys.exit(0)

_, session_path = bus.call_sync(
    'org.freedesktop.secrets',
    '/org/freedesktop/secrets',
    'org.freedesktop.Secret.Service',
    'OpenSession',
    GLib.Variant('(sv)', ('plain', GLib.Variant('s', ''))),
    GLib.VariantType('(vo)'),
    Gio.DBusCallFlags.NONE,
    3000,
    None,
).unpack()

bus.call_sync(
    'org.freedesktop.secrets',
    '/org/freedesktop/secrets',
    'org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface',
    'UnlockWithMasterPassword',
    GLib.Variant('(o(oayays))', (
        '/org/freedesktop/secrets/collection/login',
        (session_path, b'', pw, 'text/plain'),
    )),
    None,
    Gio.DBusCallFlags.NONE,
    4000,
    None,
)

print('UNLOCKED' if not get_locked() else 'STILL_LOCKED')
`

// Result captures the outcome of an attempt to unlock the Linux GNOME login keyring.
type Result struct {
	OK            bool
	KeyringLocked bool
	Error         string
}

// Handler probes and unlocks the host login keyring.
type Handler interface {
	IsLocked(ctx context.Context) *bool
	Unlock(ctx context.Context, password string) Result
}

type osHandler struct {
	goos       string
	dbusAddrFn func() string
	homeDirFn  func() (string, error)
}

// NewOSHandler returns the OS-backed GNOME login keyring handler.
func NewOSHandler() Handler {
	return &osHandler{
		goos:       runtime.GOOS,
		dbusAddrFn: resolveDbusSessionAddress,
		homeDirFn:  os.UserHomeDir,
	}
}

func resolveDbusSessionAddress() string {
	if fromEnv := strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")); fromEnv != "" {
		return fromEnv
	}
	if runtime.GOOS == "linux" {
		if uid := os.Getuid(); uid >= 0 {
			busSocket := fmt.Sprintf("/run/user/%d/bus", uid)
			if _, err := os.Stat(busSocket); err == nil {
				return "unix:path=" + busSocket
			}
		}
	}
	return ""
}

func parseGdbusLockedOutput(out string) *bool {
	trimmed := strings.TrimSpace(out)
	if strings.Contains(trimmed, "true") {
		v := true
		return &v
	}
	if strings.Contains(trimmed, "false") {
		v := false
		return &v
	}
	return nil
}

func withEnv(base []string, key, val string) []string {
	prefix := key + "="
	out := make([]string, 0, len(base)+1)
	replaced := false
	for _, entry := range base {
		if strings.HasPrefix(entry, prefix) {
			if !replaced {
				out = append(out, prefix+val)
				replaced = true
			}
			continue
		}
		out = append(out, entry)
	}
	if !replaced {
		out = append(out, prefix+val)
	}
	return out
}

func clearStaleKeyringTimeoutMarkers(homeDir string) {
	if strings.TrimSpace(homeDir) == "" {
		return
	}
	paths := []string{
		filepath.Join(homeDir, ".gemini", "antigravity-cli", "cache", keyringTimeoutMarkerFilename),
		filepath.Join(homeDir, "snap", "antigravity-cli", "common", ".gemini", "antigravity-cli", "cache", keyringTimeoutMarkerFilename),
	}
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}

func (h *osHandler) IsLocked(ctx context.Context) *bool {
	if h.goos != "linux" {
		return nil
	}
	dbusAddr := h.dbusAddrFn()
	if dbusAddr == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		runCtx,
		"gdbus",
		"call",
		"--session",
		"--dest", "org.freedesktop.secrets",
		"--object-path", "/org/freedesktop/secrets/collection/login",
		"--method", "org.freedesktop.DBus.Properties.Get",
		"org.freedesktop.Secret.Collection",
		"Locked",
	)
	cmd.Env = withEnv(os.Environ(), "DBUS_SESSION_BUS_ADDRESS", dbusAddr)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseGdbusLockedOutput(string(out))
}

func (h *osHandler) Unlock(ctx context.Context, password string) Result {
	if h.goos != "linux" {
		return Result{
			OK:            false,
			KeyringLocked: false,
			Error:         fmt.Sprintf("keyring unlock is only supported on Linux (got %s)", h.goos),
		}
	}
	dbusAddr := h.dbusAddrFn()
	if dbusAddr == "" {
		return Result{
			OK:            false,
			KeyringLocked: true,
			Error:         "D-Bus session bus is unavailable on this host.",
		}
	}
	if password == "" {
		return Result{
			OK:            false,
			KeyringLocked: true,
			Error:         "Keyring password cannot be empty.",
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "python3", "-c", pythonUnlockScript)
	// Stream password strictly via stdin so it never appears in argv or environment variables.
	cmd.Stdin = strings.NewReader(password)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = withEnv(os.Environ(), "DBUS_SESSION_BUS_ADDRESS", dbusAddr)

	err := cmd.Run()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return Result{
			OK:            false,
			KeyringLocked: true,
			Error:         "Timed out waiting for GNOME Keyring to respond.",
		}
	}

	out := strings.TrimSpace(stdout.String())
	if err == nil && out == "UNLOCKED" {
		if homeDir, hErr := h.homeDirFn(); hErr == nil {
			clearStaleKeyringTimeoutMarkers(homeDir)
		}
		return Result{OK: true, KeyringLocked: false}
	}
	if out == "STILL_LOCKED" {
		return Result{
			OK:            false,
			KeyringLocked: true,
			Error:         "Incorrect keyring password.",
		}
	}

	if errLine := lastNonEmptyLine(stderr.String()); errLine != "" {
		return Result{
			OK:            false,
			KeyringLocked: true,
			Error:         "Failed to unlock keyring: " + errLine,
		}
	}
	if err != nil {
		return Result{
			OK:            false,
			KeyringLocked: true,
			Error:         "Failed to unlock keyring: " + err.Error(),
		}
	}
	return Result{
		OK:            false,
		KeyringLocked: true,
		Error:         "Failed to unlock keyring.",
	}
}
