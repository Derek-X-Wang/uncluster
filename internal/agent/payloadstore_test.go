package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *PayloadStore {
	t.Helper()
	s := NewPayloadStore(t.TempDir())
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s
}

func stage(t *testing.T, s *PayloadStore, version, content string) string {
	t.Helper()
	p, err := s.Stage(version, strings.NewReader(content))
	if err != nil {
		t.Fatalf("Stage %s: %v", version, err)
	}
	return p
}

func TestPayloadStore_StageActivateCurrent(t *testing.T) {
	s := newTestStore(t)

	// No current yet.
	if _, _, err := s.Current(); err != ErrNoCurrent {
		t.Fatalf("Current before activate: want ErrNoCurrent, got %v", err)
	}

	binPath := stage(t, s, "v0.0.1", "BINARY-1")
	if _, err := os.Stat(binPath); err != nil {
		t.Fatalf("staged binary missing: %v", err)
	}
	// Staged binary is executable (0755).
	if info, _ := os.Stat(binPath); info.Mode().Perm() != 0o755 {
		t.Errorf("staged binary mode = %o, want 0755", info.Mode().Perm())
	}
	// Staging does not activate.
	if _, _, err := s.Current(); err != ErrNoCurrent {
		t.Errorf("Current after stage-only: want ErrNoCurrent, got %v", err)
	}

	if err := s.Activate("v0.0.1"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	got, gotVer, err := s.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if gotVer != "v0.0.1" {
		t.Errorf("current version = %q, want v0.0.1", gotVer)
	}
	if b, _ := os.ReadFile(got); string(b) != "BINARY-1" {
		t.Errorf("current resolves to wrong binary content %q", b)
	}
}

func TestPayloadStore_ActivateMovesCurrentToPrevious(t *testing.T) {
	s := newTestStore(t)
	stage(t, s, "v0.0.1", "OLD")
	stage(t, s, "v0.0.2", "NEW")

	if err := s.Activate("v0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate("v0.0.2"); err != nil {
		t.Fatal(err)
	}

	_, curVer, _ := s.Current()
	if curVer != "v0.0.2" {
		t.Errorf("current = %q, want v0.0.2", curVer)
	}
	prevPath, prevVer, err := s.Previous()
	if err != nil {
		t.Fatalf("Previous: %v", err)
	}
	if prevVer != "v0.0.1" {
		t.Errorf("previous = %q, want v0.0.1", prevVer)
	}
	if b, _ := os.ReadFile(prevPath); string(b) != "OLD" {
		t.Errorf("previous resolves to %q, want OLD", b)
	}
}

func TestPayloadStore_Rollback(t *testing.T) {
	s := newTestStore(t)
	stage(t, s, "v1", "GOOD")
	stage(t, s, "v2", "BAD")
	if err := s.Activate("v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate("v2"); err != nil {
		t.Fatal(err)
	}

	rolledTo, err := s.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rolledTo != "v1" {
		t.Errorf("rolled back to %q, want v1", rolledTo)
	}
	cur, curVer, _ := s.Current()
	if curVer != "v1" {
		t.Errorf("after rollback current = %q, want v1", curVer)
	}
	if b, _ := os.ReadFile(cur); string(b) != "GOOD" {
		t.Errorf("after rollback current resolves to %q, want GOOD", b)
	}
}

func TestPayloadStore_RollbackWithoutPreviousFails(t *testing.T) {
	s := newTestStore(t)
	stage(t, s, "v1", "ONLY")
	if err := s.Activate("v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(); err == nil {
		t.Fatal("Rollback with no previous should fail")
	}
}

func TestPayloadStore_Quarantine(t *testing.T) {
	s := newTestStore(t)
	stage(t, s, "v9", "BADVER")

	if s.IsQuarantined("v9") {
		t.Fatal("v9 quarantined before marking")
	}
	if err := s.Quarantine("v9"); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if !s.IsQuarantined("v9") {
		t.Error("v9 not quarantined after marking")
	}
	// Activation of a quarantined version is refused.
	if err := s.Activate("v9"); err == nil {
		t.Error("Activate of quarantined version should fail")
	}
}

func TestPayloadStore_AtomicSwapNoWindow(t *testing.T) {
	// After Activate, current must always resolve to a real, readable binary —
	// there is never a no-current-binary window (the pre-#187 gap).
	s := newTestStore(t)
	stage(t, s, "a", "AAA")
	stage(t, s, "b", "BBB")
	if err := s.Activate("a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate("b"); err != nil {
		t.Fatal(err)
	}
	cur, _, err := s.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if _, err := os.Stat(cur); err != nil {
		t.Errorf("current does not resolve to a real file: %v", err)
	}
}

func TestPayloadStore_ActivateUnstagedFails(t *testing.T) {
	s := newTestStore(t)
	if err := s.Activate("never-staged"); err == nil {
		t.Fatal("activating an unstaged version should fail")
	}
}

func TestPayloadStore_VersionValidation(t *testing.T) {
	s := newTestStore(t)
	for _, bad := range []string{"", ".", "..", "a/b", "../etc", "v1/../v2", "v\x00"} {
		if _, err := s.Stage(bad, strings.NewReader("x")); err == nil {
			t.Errorf("Stage(%q) should reject unsafe version", bad)
		}
	}
	// A staged bad version must never escape the versions dir.
	entries, _ := os.ReadDir(s.versionsDir())
	for _, e := range entries {
		if strings.Contains(e.Name(), "..") || strings.Contains(e.Name(), "/") {
			t.Errorf("unsafe version dir created: %q", e.Name())
		}
	}
}

func TestPayloadStore_CurrentIsSymlinkSwap(t *testing.T) {
	// current must be a symlink (so exec of the pointer follows to the version
	// binary), and re-activation replaces it atomically without leaving a
	// current.tmp behind.
	s := newTestStore(t)
	stage(t, s, "x", "X")
	if err := s.Activate("x"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(s.currentLink())
	if err != nil {
		t.Fatalf("lstat current: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("current is not a symlink (mode %v)", fi.Mode())
	}
	if _, err := os.Lstat(s.currentLink() + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("current.tmp left behind after swap")
	}
}

func TestPayloadStore_InitIdempotent(t *testing.T) {
	dir := t.TempDir()
	s := NewPayloadStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err != nil {
		t.Fatalf("second Init should be idempotent: %v", err)
	}
	for _, d := range []string{"versions", "quarantine"} {
		if _, err := os.Stat(filepath.Join(dir, d)); err != nil {
			t.Errorf("Init did not create %s: %v", d, err)
		}
	}
}
