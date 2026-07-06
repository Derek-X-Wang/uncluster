//go:build !windows

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// writeScript writes an executable /bin/sh script and returns its path.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "payload.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The runner passes UNCLUSTER_HEALTH_MARKER to the child and clears any stale
// marker before starting it.
func TestExecRunner_PassesMarkerEnvAndClearsStale(t *testing.T) {
	dir := t.TempDir()
	markerPath := filepath.Join(dir, "health")
	envOut := filepath.Join(dir, "env-seen")

	// Stale marker that Start must remove.
	if err := os.WriteFile(markerPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Child records the env var it received, then blocks until signalled.
	bin := writeScript(t, `printf '%s' "$UNCLUSTER_HEALTH_MARKER" > `+envOut+`
trap 'exit 0' TERM
while true; do sleep 0.05; done`)

	r := newExecRunner(markerPath, testLogger(t))
	r.grace = 500 * time.Millisecond
	proc, err := r.Start(context.Background(), bin)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = proc.Stop(context.Background()) }()

	// Stale marker cleared by Start.
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Errorf("stale health marker not cleared by Start")
	}
	// Child saw the marker env.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(envOut); err == nil && string(b) == markerPath {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, _ := os.ReadFile(envOut)
	t.Errorf("child UNCLUSTER_HEALTH_MARKER = %q, want %q", got, markerPath)
}

// Stop SIGTERMs a well-behaved child, which exits before the grace period.
func TestExecProcess_StopGracefulSIGTERM(t *testing.T) {
	bin := writeScript(t, `trap 'exit 0' TERM
while true; do sleep 0.05; done`)
	r := newExecRunner("", testLogger(t))
	r.grace = 3 * time.Second
	proc, err := r.Start(context.Background(), bin)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	start := time.Now()
	if err := proc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Errorf("graceful stop took %v; SIGTERM should have exited the child well before grace", elapsed)
	}
	// Child exited via SIGTERM ⇒ Wait reports a signal error.
	if err := proc.Wait(); err == nil {
		t.Log("child exited 0 on SIGTERM (trap handled)")
	}
}

// Stop escalates to SIGKILL when the child ignores SIGTERM past the grace window.
func TestExecProcess_StopEscalatesToSIGKILL(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	// Ignore TERM entirely (only SIGKILL can stop this), and signal readiness
	// AFTER the trap is installed so Stop's first SIGTERM cannot win a race with
	// trap setup.
	bin := writeScript(t, `trap '' TERM
: > `+ready+`
while true; do sleep 0.05; done`)
	r := newExecRunner("", testLogger(t))
	r.grace = 200 * time.Millisecond
	proc, err := r.Start(context.Background(), bin)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Wait until the trap is installed.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(ready); err != nil {
		_ = proc.Stop(context.Background())
		t.Fatal("child never signalled readiness (trap not installed)")
	}
	start := time.Now()
	if err := proc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("stop returned in %v; expected to wait the grace window before SIGKILL", elapsed)
	}
	// SIGKILLed child ⇒ Wait reports an error (killed).
	if err := proc.Wait(); err == nil {
		t.Errorf("Wait after SIGKILL should report a non-nil exit error")
	}
}

// Wait propagates the child's non-zero exit status.
func TestExecProcess_WaitPropagatesExitStatus(t *testing.T) {
	bin := writeScript(t, `exit 7`)
	r := newExecRunner("", testLogger(t))
	proc, err := r.Start(context.Background(), bin)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	err = proc.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Wait error = %v, want *exec.ExitError", err)
	}
	if code := exitErr.ExitCode(); code != 7 {
		t.Errorf("child exit code = %d, want 7", code)
	}
}
