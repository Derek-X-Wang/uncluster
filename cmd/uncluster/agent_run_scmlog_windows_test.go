//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSCMErrorLogPath asserts the SCM error log lands in the same
// C:\ProgramData\uncluster tree as the system config, named agent.err.log.
func TestSCMErrorLogPath(t *testing.T) {
	got := scmErrorLogPath()
	if filepath.Base(got) != scmErrorLogName {
		t.Errorf("scmErrorLogPath() base = %q, want %q", filepath.Base(got), scmErrorLogName)
	}
	// It must sit in the same directory as agent.toml so all Windows agent
	// state co-locates (and honors the same PROGRAMDATA base).
	if !strings.Contains(strings.ToLower(got), `uncluster`) {
		t.Errorf("scmErrorLogPath() = %q, want it under the uncluster ProgramData dir", got)
	}
	if strings.HasSuffix(strings.ToLower(got), ".toml") {
		t.Errorf("scmErrorLogPath() = %q, must not be the config file", got)
	}
}

// TestOpenSCMErrorLog_CreatesAndAppends verifies the redirect wiring: the log
// is created if absent, opened in APPEND mode (so it accumulates across runs),
// and content written through the returned writer lands in the file with the
// full text intact — the diagnostic that was invisible under NUL before (#128).
func TestOpenSCMErrorLog_CreatesAndAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.err.log")

	// File absent → openSCMErrorLog must create it.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("precondition: log should not exist yet")
	}
	w1, err := openSCMErrorLog(path)
	if err != nil {
		t.Fatalf("openSCMErrorLog (create): %v", err)
	}
	line1 := time.Now().UTC().Format(time.RFC3339) + " startup failure: cannot read agent.toml\n"
	if _, err := w1.Write([]byte(line1)); err != nil {
		t.Fatalf("write line1: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("close w1: %v", err)
	}

	// Re-open (simulating a service restart) → APPEND, not truncate.
	w2, err := openSCMErrorLog(path)
	if err != nil {
		t.Fatalf("openSCMErrorLog (append): %v", err)
	}
	line2 := time.Now().UTC().Format(time.RFC3339) + " second failure\n"
	if _, err := w2.Write([]byte(line2)); err != nil {
		t.Fatalf("write line2: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("close w2: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, "cannot read agent.toml") {
		t.Errorf("log lost the first failure line; got:\n%s", got)
	}
	if !strings.Contains(got, "second failure") {
		t.Errorf("append mode lost the second line (truncated?); got:\n%s", got)
	}
	// The first line must still precede the second — append, not overwrite.
	if i, j := strings.Index(got, "cannot read agent.toml"), strings.Index(got, "second failure"); i < 0 || j < 0 || i > j {
		t.Errorf("append ordering wrong; got:\n%s", got)
	}
}

// TestOpenSCMErrorLog_CreatesParentDir verifies the dir is created when the
// ProgramData\uncluster tree does not exist yet (first run before install
// populated it).
func TestOpenSCMErrorLog_CreatesParentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "uncluster") // does not exist yet
	path := filepath.Join(dir, "agent.err.log")
	w, err := openSCMErrorLog(path)
	if err != nil {
		t.Fatalf("openSCMErrorLog should create the parent dir: %v", err)
	}
	defer w.Close()
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("parent dir not created: %v", err)
	}
}
