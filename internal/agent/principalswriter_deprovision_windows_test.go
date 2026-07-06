//go:build windows

package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWindowsWriter_DeprovisionSelfStops proves the #182 control flow on Windows:
// a deprovision desired-state on the spool makes the writer WIPE the principals
// and then STOP ON ITS OWN (Run returns without any external cancel), which is
// what lets the SCM finalize the service deletion. The real mgr.Delete() is
// pointed at a bogus, non-existent service name so this unit test can never touch
// a real UnclusterPrincipalsWriter service — the OpenService failure is logged
// and swallowed exactly like the "already gone" path, and tick still self-stops.
// The genuine service removal is validated end-to-end by the t2-windows
// writer-gone probe.
func TestWindowsWriter_DeprovisionSelfStops(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PROGRAMDATA", base)

	principalsDir := filepath.Join(base, "ssh", "auth_principals")
	if err := os.MkdirAll(principalsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A pre-existing per-user file the deprovision wipe must remove.
	if err := os.WriteFile(filepath.Join(principalsDir, "derek"), []byte("caller_x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Put a deprovision signal on the spool BEFORE the writer starts.
	if err := ensureSpoolDir(); err != nil {
		t.Fatal(err)
	}
	b, _ := marshalDesiredState(deprovisionDesiredState())
	if err := atomicWriteSpoolFile(spoolPolicyPath(), b); err != nil {
		t.Fatal(err)
	}

	w := NewPrincipalsWriter(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	w.principals = principalsDir
	w.poll = 20 * time.Millisecond
	// CRITICAL: never let the test delete a real service.
	w.serviceName = "UnclusterPrincipalsWriter_UNITTEST_DOES_NOT_EXIST"

	// No cancel — the writer must stop ITSELF on the deprovision signal.
	done := make(chan error, 1)
	go func() { done <- w.Run(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error on self-stop: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not self-stop on a deprovision signal within 3s")
	}

	// The wipe must have happened before the self-stop.
	if _, err := os.Stat(filepath.Join(principalsDir, "derek")); !os.IsNotExist(err) {
		t.Fatalf("deprovision did not wipe the principals file (stat err=%v)", err)
	}
}
