package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestPollApplied_Success verifies the poll resolves as soon as read() reports a
// matching applied-status, returning it with resolved=true and no error.
func TestPollApplied_Success(t *testing.T) {
	var calls atomic.Int64
	read := func() (appliedStatus, bool) {
		// Report "not yet" for the first two polls, then a matching "ok".
		if calls.Add(1) < 3 {
			return appliedStatus{}, false
		}
		return appliedStatus{AppliedVersion: 7, AppliedHash: "h", Status: "ok"}, true
	}

	deadline := time.Now().Add(5 * time.Second)
	st, resolved, err := pollApplied(context.Background(), deadline, 5*time.Millisecond, read)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resolved {
		t.Fatal("expected resolved=true when read() reports a matching status")
	}
	if st.Status != "ok" || st.AppliedVersion != 7 {
		t.Errorf("got %+v, want version=7 status=ok", st)
	}
}

// TestPollApplied_Timeout verifies that with no matching status the poll returns
// resolved=false and NO error once the deadline elapses — the caller renders the
// visible timeout error (#127: a writer failure must surface, not hang forever).
func TestPollApplied_Timeout(t *testing.T) {
	read := func() (appliedStatus, bool) { return appliedStatus{}, false }

	start := time.Now()
	deadline := start.Add(60 * time.Millisecond)
	st, resolved, err := pollApplied(context.Background(), deadline, 15*time.Millisecond, read)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("timeout must not return an error, got: %v", err)
	}
	if resolved {
		t.Fatalf("expected resolved=false on timeout, got status %+v", st)
	}
	if elapsed < 60*time.Millisecond {
		t.Errorf("returned before deadline (%v < 60ms)", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("timeout overshot badly (%v)", elapsed)
	}
}

// TestPollApplied_CancelsPromptly is the core #153 regression: with a far-off
// deadline (simulating the 30s writer wait) and no matching status, cancelling
// the context must make the poll return promptly with a context error — never
// blocking out the full deadline. This is what lets Agent Run() shutdown return
// quickly when the Windows PrincipalsWriter is absent or slow.
func TestPollApplied_CancelsPromptly(t *testing.T) {
	read := func() (appliedStatus, bool) { return appliedStatus{}, false }

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after the poll starts, well before the far deadline.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	deadline := start.Add(30 * time.Second) // mirrors applyTimeout
	_, resolved, err := pollApplied(ctx, deadline, 250*time.Millisecond, read)
	elapsed := time.Since(start)

	if resolved {
		t.Fatal("expected resolved=false when cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("poll did not return promptly on cancel: %v (deadline was 30s away)", elapsed)
	}
}
