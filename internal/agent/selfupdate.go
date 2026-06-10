package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/version"
)

// ErrChecksumMismatch is returned when the downloaded binary's SHA256 does not
// match the published checksum file.
var ErrChecksumMismatch = errors.New("selfupdate: SHA256 checksum mismatch")

// ErrPinned is returned when the agent has a local version pin that blocks the update.
var ErrPinned = errors.New("selfupdate: version pinned locally; skipping")

// Updater handles agent binary self-update logic.
type Updater struct {
	// BinaryPath is the path to the running executable. Defaults to os.Executable().
	BinaryPath string
	// HTTPClient is used to download assets. Defaults to a client with a 5m timeout.
	HTTPClient *http.Client
	// Logger for progress/errors.
	Logger *slog.Logger
	// PinnedVersion holds the locally pinned version (overrides server). Empty = follow server.
	PinnedVersion string
}

// NewUpdater returns an Updater with sensible defaults.
func NewUpdater(binaryPath, pinnedVersion string, logger *slog.Logger) *Updater {
	if logger == nil {
		logger = slog.Default()
	}
	return &Updater{
		BinaryPath:    binaryPath,
		HTTPClient:    &http.Client{Timeout: 5 * time.Minute},
		Logger:        logger,
		PinnedVersion: pinnedVersion,
	}
}

// ResolveTemplate substitutes {os}, {arch}, {version}, and {ext} in the URL
// template. {ext} is ".exe" when goos is windows and "" otherwise: release
// assets carry the native binary extension (GoReleaser appends .exe to the
// raw windows binary and that is not configurable), but the update plan holds
// ONE template string for every platform — {ext} bridges the two. Templates
// without {ext} resolve exactly as before.
func ResolveTemplate(tmpl, goos, goarch, ver string) string {
	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}
	r := strings.NewReplacer(
		"{os}", goos,
		"{arch}", goarch,
		"{version}", ver,
		"{ext}", ext,
	)
	return r.Replace(tmpl)
}

// Apply downloads the binary at assetURL, verifies its SHA256 against sha256URL,
// and atomically swaps it into place at BinaryPath. It does NOT restart the service.
//
// On success: BinaryPath+prevSuffix (.prev on Unix, .old on Windows) contains the old binary for rollback.
// On failure: no mutation; returns an error.
//
// Returns ErrPinned if PinnedVersion is set and does not match expectedVersion.
// Returns ErrChecksumMismatch if the download fails the hash check.
func (u *Updater) Apply(ctx context.Context, expectedVersion, assetURL, sha256URL string) error {
	// Check local pin: if pinned to a *different* version, block.
	if u.PinnedVersion != "" && u.PinnedVersion != expectedVersion {
		u.Logger.Info("selfupdate: version pinned, skipping",
			"pinned", u.PinnedVersion, "expected", expectedVersion)
		return ErrPinned
	}

	binaryPath := u.BinaryPath
	if binaryPath == "" {
		var err error
		binaryPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("selfupdate: resolve executable: %w", err)
		}
	}

	newPath := binaryPath + ".new"
	prevPath := binaryPath + prevSuffix

	// 1. Download new binary to .new
	u.Logger.Info("selfupdate: downloading", "url", assetURL, "version", expectedVersion)
	if err := u.download(ctx, assetURL, newPath); err != nil {
		return fmt.Errorf("selfupdate: download binary: %w", err)
	}

	// 2. Download and verify SHA256
	if sha256URL != "" {
		u.Logger.Info("selfupdate: verifying checksum", "url", sha256URL)
		if err := u.verifySHA256(ctx, newPath, sha256URL); err != nil {
			_ = os.Remove(newPath)
			return err
		}
	}

	// 3. Make new binary executable.
	if err := os.Chmod(newPath, 0o755); err != nil {
		_ = os.Remove(newPath)
		return fmt.Errorf("selfupdate: chmod .new: %w", err)
	}

	// 4. Atomic swap: current → .prev, .new → current
	if err := os.Rename(binaryPath, prevPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(newPath)
		return fmt.Errorf("selfupdate: rename to %s: %w", prevSuffix, err)
	}
	if err := os.Rename(newPath, binaryPath); err != nil {
		// Attempt rollback of the prev rename.
		_ = os.Rename(prevPath, binaryPath)
		return fmt.Errorf("selfupdate: rename .new to binary: %w", err)
	}

	u.Logger.Info("selfupdate: binary swapped", "path", binaryPath, "version", expectedVersion)
	return nil
}

// Rollback swaps BinaryPath+prevSuffix (.prev on Unix, .old on Windows) back to BinaryPath.
func (u *Updater) Rollback() error {
	binaryPath := u.BinaryPath
	if binaryPath == "" {
		var err error
		binaryPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("selfupdate: resolve executable: %w", err)
		}
	}
	prevPath := binaryPath + prevSuffix
	failedPath := binaryPath + ".failed"
	if _, err := os.Stat(prevPath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("selfupdate: no %s binary to rollback to", prevSuffix)
	}
	if err := os.Rename(binaryPath, failedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("selfupdate: rename current to .failed: %w", err)
	}
	if err := os.Rename(prevPath, binaryPath); err != nil {
		return fmt.Errorf("selfupdate: rename %s to binary: %w", prevSuffix, err)
	}
	return nil
}

// download fetches url and writes to destPath with mode 0600.
func (u *Updater) download(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	f, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// verifySHA256 downloads the checksum file at sha256URL, parses the expected
// hash, and compares it against the SHA256 of the file at filePath.
// Supports both "hex" and "hex  filename" (coreutils sha256sum) formats.
func (u *Updater) verifySHA256(ctx context.Context, filePath, sha256URL string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", sha256URL, nil)
	if err != nil {
		return err
	}
	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("selfupdate: fetch checksum: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("selfupdate: checksum fetch status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("selfupdate: read checksum: %w", err)
	}
	// First whitespace-delimited token is the hex digest.
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return fmt.Errorf("selfupdate: empty checksum file")
	}
	expectedHex := strings.ToLower(fields[0])

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actualHex := hex.EncodeToString(h.Sum(nil))

	if actualHex != expectedHex {
		return fmt.Errorf("%w: got %s want %s", ErrChecksumMismatch, actualHex, expectedHex)
	}
	return nil
}

// HandleCheckUpdate is called by the agent loop when the server sends a
// check_update command. Fetches the update plan, checks if update is needed,
// and delegates download+swap to Updater.Apply, then calls restartService.
func (a *Agent) HandleCheckUpdate(ctx context.Context, _ api.CheckUpdateCommand) error {
	plan, err := a.client.GetUpdatePlan(ctx)
	if err != nil {
		return fmt.Errorf("get-update-plan: %w", err)
	}
	if plan.ExpectedVersion == "" {
		a.logger.Info("selfupdate: server mandates no update")
		return nil
	}

	current := version.Version
	if current == plan.ExpectedVersion && !plan.Force {
		a.logger.Info("selfupdate: already on expected version", "version", current)
		return nil
	}

	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("selfupdate: resolve executable: %w", err)
	}

	assetURL := ResolveTemplate(plan.AssetURLTemplate, runtime.GOOS, runtime.GOARCH, plan.ExpectedVersion)
	sha256URL := ResolveTemplate(plan.SHA256URLTemplate, runtime.GOOS, runtime.GOARCH, plan.ExpectedVersion)

	// Enforce the install-time-pinned host allowlist BEFORE any HTTP
	// request. A compromised Control plane can hand back any URLs; this
	// is the last-mile defence that keeps the Agent from fetching from
	// an attacker-controlled host even if SHA256 verification is
	// also compromised (the same compromise hands back a matching
	// .sha256 file). See ADR-0006 + #39.
	allowlist := a.cfg.AllowedUpdateHosts()
	if err := ValidateUpdateURL(assetURL, allowlist); err != nil {
		a.logger.Error("selfupdate: asset URL rejected",
			"component", "selfupdate",
			"reason", "disallowed_host",
			"url", assetURL,
			"allowlist", allowlist,
			"err", err,
		)
		return err
	}
	if sha256URL != "" {
		if err := ValidateUpdateURL(sha256URL, allowlist); err != nil {
			a.logger.Error("selfupdate: sha256 URL rejected",
				"component", "selfupdate",
				"reason", "disallowed_host",
				"url", sha256URL,
				"allowlist", allowlist,
				"err", err,
			)
			return err
		}
	}

	updater := NewUpdater(binaryPath, a.cfg.PinnedVersion, a.logger)
	if err := updater.Apply(ctx, plan.ExpectedVersion, assetURL, sha256URL); err != nil {
		if errors.Is(err, ErrPinned) {
			return nil
		}
		return err
	}

	return a.restartService(ctx)
}
