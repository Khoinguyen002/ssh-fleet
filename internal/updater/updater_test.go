package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.2.0", "v1.1.0", 1},
		{"1.2.0", "v1.2.0", 0},
		{"v1.1.9", "v1.2.0", -1},
		{"v2.0.0", "v1.99.99", 1},
		{"v1.2.0", "dev", 0},
		{"dev", "v1.2.0", 0},
		{"bad", "v1.0.0", 0},
	}
	for _, tc := range tests {
		if got := CompareSemver(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareSemver(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	for _, tc := range []struct {
		goos, goarch string
		want         string
		wantErr      bool
	}{
		{"linux", "amd64", "sf-linux-amd64", false},
		{"linux", "arm64", "sf-linux-arm64", false},
		{"darwin", "amd64", "sf-darwin-amd64", false},
		{"darwin", "arm64", "sf-darwin-arm64", false},
		{"windows", "amd64", "sf-windows-amd64.exe", false},
		{"freebsd", "amd64", "", true},
	} {
		got, err := AssetName(tc.goos, tc.goarch)
		if (err != nil) != tc.wantErr {
			t.Fatalf("AssetName(%s,%s) err=%v wantErr=%v", tc.goos, tc.goarch, err, tc.wantErr)
		}
		if got != tc.want {
			t.Fatalf("AssetName(%s,%s) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestParseChecksumFile(t *testing.T) {
	sum := strings.Repeat("a", 64)
	content := fmt.Sprintf("%s  sf-linux-amd64\n%s *sf-darwin-arm64\n", sum, strings.Repeat("b", 64))
	got, ok := ParseChecksumFile(content, "sf-linux-amd64")
	if !ok || got != sum {
		t.Fatalf("unexpected parse result: ok=%v got=%q", ok, got)
	}
	got2, ok2 := ParseChecksumFile(content, "sf-darwin-arm64")
	if !ok2 || got2 != strings.Repeat("b", 64) {
		t.Fatalf("unexpected binary-star parse result: ok=%v got=%q", ok2, got2)
	}
	if _, ok := ParseChecksumFile(content, "missing"); ok {
		t.Fatalf("expected missing asset not found")
	}
}

func TestCheckAndApplyMockRelease(t *testing.T) {
	asset, err := AssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skipf("unsupported test platform: %v", err)
	}

	newPayload := bytes.Repeat([]byte("sf-v1.2.0-binary-"), 120)
	h := sha256.Sum256(newPayload)
	goodSum := hex.EncodeToString(h[:])
	badSum := strings.Repeat("0", 64)

	latestTag := "v1.2.0"
	serveChecksum := goodSum

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			http.Redirect(w, r, srv.URL+"/releases/tag/"+latestTag, http.StatusFound)
		case "/releases/download/" + latestTag + "/" + asset:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(newPayload)
		case "/releases/download/" + latestTag + "/SHA256SUMS.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "%s  %s\n", serveChecksum, asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "sf")
	origPayload := []byte("original-v1.1.0-binary")
	if err := os.WriteFile(target, origPayload, 0755); err != nil {
		t.Fatalf("write target: %v", err)
	}

	// 1. Same version -> no-op.
	resSame, err := CheckAndApply(context.Background(), Options{
		RepoBaseURL:     srv.URL,
		CurrentVersion:  "v1.2.0",
		TargetPath:      target,
		RequireChecksum: true,
	})
	if err != nil || resSame.Updated || resSame.LatestVersion != "v1.2.0" {
		t.Fatalf("expected no-op for v1.2.0, got res=%+v err=%v", resSame, err)
	}

	// 2. Checksum mismatch -> fails and leaves original binary untouched.
	serveChecksum = badSum
	if _, err := CheckAndApply(context.Background(), Options{
		RepoBaseURL:     srv.URL,
		CurrentVersion:  "v1.1.0",
		TargetPath:      target,
		RequireChecksum: true,
	}); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error, got %v", err)
	}
	gotAfterFail, _ := os.ReadFile(target)
	if !bytes.Equal(gotAfterFail, origPayload) {
		t.Fatalf("original binary modified after failed checksum")
	}

	// 3. Valid checksum -> updates atomically.
	serveChecksum = goodSum
	resOK, err := CheckAndApply(context.Background(), Options{
		RepoBaseURL:     srv.URL,
		CurrentVersion:  "v1.1.0",
		TargetPath:      target,
		RequireChecksum: true,
	})
	if err != nil || !resOK.Updated || resOK.LatestVersion != "v1.2.0" {
		t.Fatalf("expected successful update, got res=%+v err=%v", resOK, err)
	}
	gotAfterOK, _ := os.ReadFile(target)
	if !bytes.Equal(gotAfterOK, newPayload) {
		t.Fatalf("updated binary mismatch")
	}
}
