package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TestOnRevoked_RunsDeprovisionCleanup verifies the #146 fix: onRevoked invokes
// the injected deprovision-cleanup hook (on Windows, the CLI wires this to the
// LocalSystem writer uninstall so the writer never outlives the agent) and still
// completes deprovision (returns ErrDeprovisioned, writes the marker).
//
// PrincipalsDir is left empty so the wipe is skipped — the wipe routes through
// the Windows writer and would block on its absence; this test isolates the
// cleanup-hook contract, which is platform-neutral.
func TestOnRevoked_RunsDeprovisionCleanup(t *testing.T) {
	configDir := t.TempDir()
	var called atomic.Int64

	a := (&Agent{
		cfg:        Config{ExpectedPaths: ExpectedPaths{}},
		configPath: filepath.Join(configDir, "agent.toml"),
		logger:     testLogger(t),
	}).WithDeprovisionCleanup(func(context.Context) error {
		called.Add(1)
		return nil
	})

	if err := a.onRevoked(context.Background()); !errors.Is(err, ErrDeprovisioned) {
		t.Fatalf("onRevoked = %v, want ErrDeprovisioned", err)
	}
	if got := called.Load(); got != 1 {
		t.Errorf("deprovision cleanup called %d times, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(configDir, ".deprovisioned")); err != nil {
		t.Errorf("marker not written after deprovision: %v", err)
	}
}

// TestOnRevoked_DeprovisionCleanupErrorIsNonFatal pins the best-effort posture:
// if the cleanup hook fails (e.g. the low-priv agent hits access-denied deleting
// the writer service), deprovision still completes — the marker is written and
// ErrDeprovisioned is returned so the supervisor stops restarting.
func TestOnRevoked_DeprovisionCleanupErrorIsNonFatal(t *testing.T) {
	configDir := t.TempDir()

	a := (&Agent{
		cfg:        Config{ExpectedPaths: ExpectedPaths{}},
		configPath: filepath.Join(configDir, "agent.toml"),
		logger:     testLogger(t),
	}).WithDeprovisionCleanup(func(context.Context) error {
		return errors.New("access denied deleting writer service")
	})

	if err := a.onRevoked(context.Background()); !errors.Is(err, ErrDeprovisioned) {
		t.Fatalf("onRevoked = %v, want ErrDeprovisioned despite cleanup error", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, ".deprovisioned")); err != nil {
		t.Errorf("marker not written when cleanup errored: %v", err)
	}
}

// TestOnRevoked_NilDeprovisionCleanup verifies the Unix/default path (no hook)
// is unchanged — onRevoked must not panic when no cleanup is injected.
func TestOnRevoked_NilDeprovisionCleanup(t *testing.T) {
	configDir := t.TempDir()
	a := &Agent{
		cfg:        Config{ExpectedPaths: ExpectedPaths{}},
		configPath: filepath.Join(configDir, "agent.toml"),
		logger:     testLogger(t),
	}
	if err := a.onRevoked(context.Background()); !errors.Is(err, ErrDeprovisioned) {
		t.Fatalf("onRevoked (nil cleanup) = %v, want ErrDeprovisioned", err)
	}
}
