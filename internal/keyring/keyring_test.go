package keyring

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGdbusLockedOutput(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want *bool
	}{
		{name: "locked true", out: "(<true>,)\n", want: boolPtr(true)},
		{name: "locked false", out: "(<false>,)\n", want: boolPtr(false)},
		{name: "empty", out: "", want: nil},
		{name: "unexpected", out: "(<unknown>,)", want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseGdbusLockedOutput(tc.out)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", *got)
				}
				return
			}
			if got == nil || *got != *tc.want {
				t.Fatalf("got %v, want %v", got, *tc.want)
			}
		})
	}
}

func TestClearStaleKeyringTimeoutMarkers(t *testing.T) {
	home := t.TempDir()
	markers := []string{
		filepath.Join(home, ".gemini", "antigravity-cli", "cache", keyringTimeoutMarkerFilename),
		filepath.Join(home, "snap", "antigravity-cli", "common", ".gemini", "antigravity-cli", "cache", keyringTimeoutMarkerFilename),
	}
	for _, m := range markers {
		if err := os.MkdirAll(filepath.Dir(m), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", m, err)
		}
		if err := os.WriteFile(m, []byte("1"), 0644); err != nil {
			t.Fatalf("write %s: %v", m, err)
		}
	}

	clearStaleKeyringTimeoutMarkers(home)

	for _, m := range markers {
		if _, err := os.Stat(m); !os.IsNotExist(err) {
			t.Fatalf("expected marker %s to be removed, stat err=%v", m, err)
		}
	}
}

func TestUnlockPreconditions(t *testing.T) {
	nonLinux := &osHandler{
		goos:       "darwin",
		dbusAddrFn: func() string { return "unix:path=/run/user/1000/bus" },
		homeDirFn:  os.UserHomeDir,
	}
	if got := nonLinux.IsLocked(context.Background()); got != nil {
		t.Fatalf("expected nil IsLocked on non-Linux, got %v", *got)
	}
	res := nonLinux.Unlock(context.Background(), "secret")
	if res.OK || res.KeyringLocked || !strings.Contains(res.Error, "only supported on Linux") {
		t.Fatalf("unexpected non-Linux unlock result: %+v", res)
	}

	noDbus := &osHandler{
		goos:       "linux",
		dbusAddrFn: func() string { return "" },
		homeDirFn:  os.UserHomeDir,
	}
	if got := noDbus.IsLocked(context.Background()); got != nil {
		t.Fatalf("expected nil IsLocked without D-Bus, got %v", *got)
	}
	resNoDbus := noDbus.Unlock(context.Background(), "secret")
	if resNoDbus.OK || !resNoDbus.KeyringLocked || !strings.Contains(resNoDbus.Error, "D-Bus session bus is unavailable") {
		t.Fatalf("unexpected no-DBus unlock result: %+v", resNoDbus)
	}

	emptyPw := &osHandler{
		goos:       "linux",
		dbusAddrFn: func() string { return "unix:path=/run/user/1000/bus" },
		homeDirFn:  os.UserHomeDir,
	}
	resEmpty := emptyPw.Unlock(context.Background(), "")
	if resEmpty.OK || !resEmpty.KeyringLocked || !strings.Contains(resEmpty.Error, "cannot be empty") {
		t.Fatalf("unexpected empty password unlock result: %+v", resEmpty)
	}
}

func boolPtr(v bool) *bool { return &v }
