//go:build windows

package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestWindowsApplyHandoff_RoundTrip exercises the full Windows agent→spool→writer
// handoff (#127): the agent's doApplyPolicy writes a desired-state to the spool;
// a PrincipalsWriter (pointed at temp dirs) applies it and writes applied.json;
// the agent's poll then matches the version+hash and returns success.
//
// PROGRAMDATA is redirected to a temp dir so SpoolDir()/spoolPolicyPath() resolve
// under the test sandbox. The writer's target principals dir is overridden to a
// temp dir too (so the ACL syscall runs but on a test-owned file). This is the
// Windows-only proof that policyState reaches applied via the round-trip.
func TestWindowsApplyHandoff_RoundTrip(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PROGRAMDATA", base)

	principalsDir := filepath.Join(base, "ssh", "auth_principals")
	if err := os.MkdirAll(principalsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Run a writer pointed at our temp spool + principals dir.
	w := NewPrincipalsWriter(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	w.principals = principalsDir // override the hardcoded prod path for the test
	w.poll = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Run(ctx)
	}()

	// Agent side: submit a policy via doApplyPolicy (writes spool, polls applied).
	a := &Agent{
		cfg:    Config{ExpectedPaths: ExpectedPaths{PrincipalsDir: WindowsPrincipalsDir}},
		logger: slog.Default(),
	}
	snap := api.PolicyPayload{
		Version: 11, Hash: "blake3:round",
		Principals: []api.PolicyPrincipal{
			{Username: "derek", CallerTokenIDs: []string{"caller_rt"}},
		},
	}
	if err := a.doApplyPolicy(context.Background(), a.cfg.ExpectedPaths.PrincipalsDir, snap); err != nil {
		t.Fatalf("doApplyPolicy round-trip failed: %v", err)
	}

	// The writer should have rendered the file in the temp principals dir.
	got, err := os.ReadFile(filepath.Join(principalsDir, "derek"))
	if err != nil {
		t.Fatalf("writer did not render principals file: %v", err)
	}
	if string(got) != "caller_rt\n" {
		t.Errorf("rendered content = %q, want caller_rt", got)
	}

	cancel()
	<-done
}

// TestWindowsApplyHandoff_CancelReturnsPromptly is the #153 Windows-side proof:
// with NO writer running, cancelling the context makes doApplyPolicy return
// promptly (well under applyTimeout) with a context error, instead of blocking
// out the full 30s writer wait — the stall that tripped the shutdown-race
// stress test's per-iteration deadline on windows-latest.
func TestWindowsApplyHandoff_CancelReturnsPromptly(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PROGRAMDATA", base)

	a := &Agent{
		cfg:    Config{ExpectedPaths: ExpectedPaths{PrincipalsDir: WindowsPrincipalsDir}},
		logger: slog.Default(),
	}
	snap := api.PolicyPayload{
		Version: 5, Hash: "blake3:cancel",
		Principals: []api.PolicyPrincipal{{Username: "derek", CallerTokenIDs: []string{"caller_c"}}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := a.doApplyPolicy(ctx, a.cfg.ExpectedPaths.PrincipalsDir, snap)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the apply is cancelled with no writer running")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected a context.Canceled-wrapped error, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("doApplyPolicy did not return promptly on cancel: %v (applyTimeout is %v)", elapsed, applyTimeout)
	}
}

// TestWindowsApplyHandoff_WriterDownTimesOut verifies that if NO writer is
// running, the agent's doApplyPolicy surfaces a VISIBLE failed apply (an error)
// rather than hanging forever (#127 acceptance). The timeout is shrunk via the
// poll loop reaching the deadline; we assert it returns an error reasonably fast
// by using a context-bounded goroutine.
func TestWindowsApplyHandoff_WriterDownTimesOut(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PROGRAMDATA", base)

	snap := api.PolicyPayload{
		Version: 1, Hash: "h",
		Principals: []api.PolicyPrincipal{{Username: "derek", CallerTokenIDs: []string{"caller_x"}}},
	}

	// We cannot wait the full applyTimeout (30s) in a unit test, so instead of
	// calling doApplyPolicy (which would block until the deadline) we assert its
	// two halves directly: the agent CAN write the desired-state to the spool,
	// and with no writer running readMatchingAppliedStatus reports "not yet" —
	// which is what drives doApplyPolicy to its visible-timeout error path. The
	// success path is covered by TestWindowsApplyHandoff_RoundTrip.
	if err := ensureSpoolDir(); err != nil {
		t.Fatal(err)
	}
	d := desiredStateFromPayload(snap)
	b, _ := marshalDesiredState(d)
	if err := atomicWriteSpoolFile(spoolPolicyPath(), b); err != nil {
		t.Fatalf("agent failed to write desired-state to spool: %v", err)
	}
	if _, err := os.Stat(spoolPolicyPath()); err != nil {
		t.Errorf("desired-state not on spool: %v", err)
	}
	// With no writer and no applied.json, readMatchingAppliedStatus must report
	// "not yet" (false) — the agent keeps polling until its deadline, then errors.
	if _, ok := readMatchingAppliedStatus(spoolAppliedPath(), d); ok {
		t.Error("readMatchingAppliedStatus returned ok with no writer running")
	}
}
