package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// ---- ResolveTemplate ----

func TestResolveTemplate(t *testing.T) {
	tests := []struct {
		tmpl, os, arch, ver, want string
	}{
		{
			"https://example.com/{os}/{arch}/uncluster-{version}",
			"linux", "amd64", "v2.1.0",
			"https://example.com/linux/amd64/uncluster-v2.1.0",
		},
		{
			"https://example.com/{os}/{arch}/uncluster-{version}.sha256",
			"darwin", "arm64", "v2.0.1",
			"https://example.com/darwin/arm64/uncluster-v2.0.1.sha256",
		},
		{
			// No substitutions.
			"https://example.com/static",
			"linux", "amd64", "v1.0.0",
			"https://example.com/static",
		},
	}
	for _, tc := range tests {
		got := ResolveTemplate(tc.tmpl, tc.os, tc.arch, tc.ver)
		if got != tc.want {
			t.Errorf("ResolveTemplate(%q, %q, %q, %q) = %q, want %q",
				tc.tmpl, tc.os, tc.arch, tc.ver, got, tc.want)
		}
	}
}

// ---- Updater.Apply ----

// testHTTPServer sets up a minimal test server that serves:
//   /binary   — the fake binary content
//   /checksum — sha256sum format: "<hex>  binary"
func testHTTPServer(t *testing.T, content []byte) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/binary":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content)
		case "/checksum":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "%s  binary\n", hexSum)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestUpdater_Apply_DownloadAndSwap(t *testing.T) {
	content := []byte("fake binary content v2")
	ts := testHTTPServer(t, content)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "agent")
	// Write an initial "current" binary.
	if err := os.WriteFile(binaryPath, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	updater := &Updater{
		BinaryPath:  binaryPath,
		HTTPClient:  ts.Client(),
		Logger:      slog.Default(),
	}
	if err := updater.Apply(context.Background(), "v2.0.0", ts.URL+"/binary", ts.URL+"/checksum"); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// New binary should be in place.
	got, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Errorf("binary content = %q, want %q", got, content)
	}

	// .prev should hold the old binary.
	prev, err := os.ReadFile(binaryPath + ".prev")
	if err != nil {
		t.Fatal(err)
	}
	if string(prev) != "old binary" {
		t.Errorf(".prev content = %q, want 'old binary'", prev)
	}
}

func TestUpdater_Apply_ChecksumMismatch(t *testing.T) {
	content := []byte("real binary")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/binary":
			_, _ = w.Write(content)
		case "/checksum":
			// Return wrong hash.
			fmt.Fprintf(w, "%s  binary\n", "deadbeef"+string(make([]byte, 56)))
		}
	}))
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "agent")
	_ = os.WriteFile(binaryPath, []byte("old"), 0o755)

	updater := &Updater{
		BinaryPath: binaryPath,
		HTTPClient: ts.Client(),
		Logger:     slog.Default(),
	}
	err := updater.Apply(context.Background(), "v2.0.0", ts.URL+"/binary", ts.URL+"/checksum")
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("want ErrChecksumMismatch, got %v", err)
	}
	// Original binary must be intact (no mutation on checksum failure).
	orig, _ := os.ReadFile(binaryPath)
	if string(orig) != "old" {
		t.Errorf("binary mutated on checksum failure: %q", orig)
	}
	// .new should be cleaned up.
	if _, err := os.Stat(binaryPath + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Error(".new should be removed on checksum failure")
	}
}

func TestUpdater_Apply_Pinned_BlocksDifferentVersion(t *testing.T) {
	content := []byte("binary v2")
	ts := testHTTPServer(t, content)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "agent")
	_ = os.WriteFile(binaryPath, []byte("old"), 0o755)

	updater := &Updater{
		BinaryPath:    binaryPath,
		HTTPClient:    ts.Client(),
		Logger:        slog.Default(),
		PinnedVersion: "v1.0.0", // pinned to v1, server wants v2
	}
	err := updater.Apply(context.Background(), "v2.0.0", ts.URL+"/binary", ts.URL+"/checksum")
	if !errors.Is(err, ErrPinned) {
		t.Fatalf("want ErrPinned, got %v", err)
	}
	// Binary unchanged.
	orig, _ := os.ReadFile(binaryPath)
	if string(orig) != "old" {
		t.Errorf("binary mutated when pinned: %q", orig)
	}
}

func TestUpdater_Apply_Pinned_AllowsSameVersion(t *testing.T) {
	content := []byte("binary v1.0.0")
	ts := testHTTPServer(t, content)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "agent")
	_ = os.WriteFile(binaryPath, []byte("old"), 0o755)

	updater := &Updater{
		BinaryPath:    binaryPath,
		HTTPClient:    ts.Client(),
		Logger:        slog.Default(),
		PinnedVersion: "v1.0.0", // pinned to same as expected
	}
	err := updater.Apply(context.Background(), "v1.0.0", ts.URL+"/binary", ts.URL+"/checksum")
	if err != nil {
		t.Fatalf("Apply with matching pin: %v", err)
	}
}

func TestUpdater_Rollback(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "agent")
	_ = os.WriteFile(binaryPath, []byte("bad new binary"), 0o755)
	_ = os.WriteFile(binaryPath+".prev", []byte("good old binary"), 0o755)

	updater := &Updater{BinaryPath: binaryPath, Logger: slog.Default()}
	if err := updater.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	got, _ := os.ReadFile(binaryPath)
	if string(got) != "good old binary" {
		t.Errorf("binary after rollback = %q, want 'good old binary'", got)
	}
	// .failed should have the bad binary.
	failed, _ := os.ReadFile(binaryPath + ".failed")
	if string(failed) != "bad new binary" {
		t.Errorf(".failed = %q, want 'bad new binary'", failed)
	}
}

func TestUpdater_Rollback_NoPrev(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "agent")
	_ = os.WriteFile(binaryPath, []byte("current"), 0o755)

	updater := &Updater{BinaryPath: binaryPath, Logger: slog.Default()}
	err := updater.Rollback()
	if err == nil {
		t.Fatal("expected error when no .prev exists")
	}
}

func TestUpdater_Apply_NoChecksumURL(t *testing.T) {
	content := []byte("binary no checksum")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "agent")
	_ = os.WriteFile(binaryPath, []byte("old"), 0o755)

	updater := &Updater{BinaryPath: binaryPath, HTTPClient: ts.Client(), Logger: slog.Default()}
	// Empty sha256URL = skip checksum verification.
	if err := updater.Apply(context.Background(), "v3.0.0", ts.URL+"/binary", ""); err != nil {
		t.Fatalf("Apply without checksum: %v", err)
	}
	got, _ := os.ReadFile(binaryPath)
	if string(got) != string(content) {
		t.Errorf("binary = %q, want %q", got, content)
	}
}
