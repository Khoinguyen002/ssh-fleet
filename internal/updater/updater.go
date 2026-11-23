package updater

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const DefaultRepo = "Khoinguyen002/ssh-fleet"

const defaultMinBinarySize = 1024

type Options struct {
	RepoBaseURL     string
	CurrentVersion  string
	TargetPath      string
	Force           bool
	RequireChecksum bool
	HTTPClient      *http.Client
}

type Result struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Updated        bool   `json:"updated"`
	BinaryPath     string `json:"binary_path,omitempty"`
}

func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return out, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i := 0; i < 3; i++ {
		if parts[i] == "" {
			return out, false
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// CompareSemver compares two vX.Y.Z strings, returning 1 if a > b, -1 if a < b,
// and 0 if equal or if either version is non-semver (such as "dev").
func CompareSemver(a, b string) int {
	pa, okA := parseSemver(a)
	pb, okB := parseSemver(b)
	if !okA || !okB {
		return 0
	}
	for i := 0; i < 3; i++ {
		if pa[i] > pb[i] {
			return 1
		}
		if pa[i] < pb[i] {
			return -1
		}
	}
	return 0
}

func AssetName(goos, goarch string) (string, error) {
	switch goos {
	case "linux", "darwin":
		if goarch == "amd64" || goarch == "arm64" {
			return fmt.Sprintf("sf-%s-%s", goos, goarch), nil
		}
	case "windows":
		if goarch == "amd64" {
			return "sf-windows-amd64.exe", nil
		}
	}
	return "", fmt.Errorf("unsupported platform %s/%s", goos, goarch)
}

func FetchLatestTag(ctx context.Context, baseURL string) (string, error) {
	return fetchLatestTag(ctx, baseURL, nil)
}

func fetchLatestTag(ctx context.Context, baseURL string, baseClient *http.Client) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = "https://github.com/" + DefaultRepo
	}

	var client http.Client
	if baseClient != nil {
		client = *baseClient
	} else {
		client = http.Client{Timeout: 15 * time.Second}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, base+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	loc := strings.TrimSpace(resp.Header.Get("Location"))
	if loc == "" {
		return "", fmt.Errorf("latest release redirect missing (HTTP %s)", resp.Status)
	}
	const marker = "/releases/tag/"
	idx := strings.LastIndex(loc, marker)
	if idx < 0 {
		return "", fmt.Errorf("unexpected release redirect location %q", loc)
	}
	tag := loc[idx+len(marker):]
	if q := strings.IndexAny(tag, "?#/"); q >= 0 {
		tag = tag[:q]
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "", errors.New("empty release tag in redirect")
	}
	return tag, nil
}

func ParseChecksumFile(content, assetName string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		sum := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[1], "*")
		if len(sum) != 64 {
			continue
		}
		if name == assetName || filepath.Base(name) == assetName {
			return sum, true
		}
	}
	return "", false
}

func resolveTargetPath(targetPath string) (string, error) {
	if strings.TrimSpace(targetPath) != "" {
		return targetPath, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rErr := filepath.EvalSymlinks(exe); rErr == nil && resolved != "" {
		return resolved, nil
	}
	return exe, nil
}

func CheckAndApply(ctx context.Context, opts Options) (Result, error) {
	targetPath, err := resolveTargetPath(opts.TargetPath)
	if err != nil {
		return Result{}, err
	}
	baseURL := strings.TrimRight(strings.TrimSpace(opts.RepoBaseURL), "/")
	if baseURL == "" {
		baseURL = "https://github.com/" + DefaultRepo
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	latestTag, err := fetchLatestTag(ctx, baseURL, client)
	if err != nil {
		return Result{CurrentVersion: opts.CurrentVersion, BinaryPath: targetPath}, err
	}

	if !opts.Force && CompareSemver(latestTag, opts.CurrentVersion) <= 0 {
		return Result{
			CurrentVersion: opts.CurrentVersion,
			LatestVersion:  latestTag,
			Updated:        false,
			BinaryPath:     targetPath,
		}, nil
	}

	asset, err := AssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return Result{CurrentVersion: opts.CurrentVersion, LatestVersion: latestTag}, err
	}

	binURL := fmt.Sprintf("%s/releases/download/%s/%s", baseURL, latestTag, asset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, binURL, nil)
	if err != nil {
		return Result{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("download %s failed: HTTP %s", asset, resp.Status)
	}

	dir := filepath.Dir(targetPath)
	tmpFile, err := os.CreateTemp(dir, ".sf-update-*")
	if err != nil {
		return Result{}, err
	}
	tmpName := tmpFile.Name()
	cleanupTmp := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}

	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmpFile, hasher), io.LimitReader(resp.Body, 128*1024*1024))
	closeErr := tmpFile.Close()
	if copyErr != nil {
		cleanupTmp()
		return Result{}, copyErr
	}
	if closeErr != nil {
		cleanupTmp()
		return Result{}, closeErr
	}
	if written < defaultMinBinarySize {
		cleanupTmp()
		return Result{}, fmt.Errorf("downloaded binary %s unexpectedly small (%d bytes)", asset, written)
	}
	gotSum := hex.EncodeToString(hasher.Sum(nil))

	sumURL := fmt.Sprintf("%s/releases/download/%s/SHA256SUMS.txt", baseURL, latestTag)
	sumReq, err := http.NewRequestWithContext(ctx, http.MethodGet, sumURL, nil)
	if err != nil {
		cleanupTmp()
		return Result{}, err
	}
	sumResp, err := client.Do(sumReq)
	if err != nil {
		cleanupTmp()
		return Result{}, err
	}
	sumBody, sumReadErr := io.ReadAll(io.LimitReader(sumResp.Body, 1024*1024))
	_ = sumResp.Body.Close()

	switch sumResp.StatusCode {
	case http.StatusOK:
		if sumReadErr != nil {
			cleanupTmp()
			return Result{}, sumReadErr
		}
		wantSum, found := ParseChecksumFile(string(sumBody), asset)
		if !found {
			cleanupTmp()
			return Result{}, fmt.Errorf("checksum entry for %s missing from SHA256SUMS.txt", asset)
		}
		if subtle.ConstantTimeCompare([]byte(gotSum), []byte(wantSum)) != 1 {
			cleanupTmp()
			return Result{}, fmt.Errorf("checksum mismatch for %s (got %s, want %s)", asset, gotSum, wantSum)
		}
	case http.StatusNotFound:
		if opts.RequireChecksum {
			cleanupTmp()
			return Result{}, errors.New("SHA256SUMS.txt not found for release (refusing unverified binary)")
		}
	default:
		cleanupTmp()
		return Result{}, fmt.Errorf("failed fetching SHA256SUMS.txt: HTTP %s", sumResp.Status)
	}

	if err := replaceBinary(tmpName, targetPath); err != nil {
		_ = os.Remove(tmpName)
		return Result{}, err
	}

	return Result{
		CurrentVersion: opts.CurrentVersion,
		LatestVersion:  latestTag,
		Updated:        true,
		BinaryPath:     targetPath,
	}, nil
}

func replaceBinary(tmpPath, targetPath string) error {
	if runtime.GOOS == "windows" {
		oldPath := targetPath + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(targetPath, oldPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(tmpPath, targetPath); err != nil {
			_ = os.Rename(oldPath, targetPath)
			return err
		}
		_ = os.Remove(oldPath)
		return nil
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return err
	}
	return os.Rename(tmpPath, targetPath)
}

// StartAutoLoop periodically checks GitHub Releases for a newer version and
// atomically replaces and re-execs the running binary. No-op for "dev" builds.
func StartAutoLoop(ctx context.Context, currentVersion string, interval, initialDelay time.Duration, onBeforeRestart func()) {
	if currentVersion == "" || currentVersion == "dev" {
		return
	}
	if initialDelay <= 0 {
		initialDelay = 1 * time.Minute
	}
	if interval <= 0 {
		interval = 30 * time.Minute
	}

	runOnce := func() bool {
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		res, err := CheckAndApply(runCtx, Options{
			CurrentVersion:  currentVersion,
			RequireChecksum: true,
		})
		cancel()
		if err != nil || !res.Updated {
			return false
		}
		if onBeforeRestart != nil {
			onBeforeRestart()
		}
		_ = ReExec(res.BinaryPath)
		return true
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(initialDelay):
	}
	if runOnce() {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if runOnce() {
				return
			}
		}
	}
}
