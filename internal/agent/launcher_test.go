package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProcess is a controllable PayloadProcess. It exits when exit is closed or
// Stop is called.
type fakeProcess struct {
	version string
	exitErr error
	exited  chan struct{}
	once    sync.Once
	stopped bool
}

func newFakeProcess(version string) *fakeProcess {
	return &fakeProcess{version: version, exited: make(chan struct{})}
}

func (p *fakeProcess) Wait() error {
	<-p.exited
	return p.exitErr
}

func (p *fakeProcess) Stop(context.Context) error {
	p.stopped = true
	p.die(nil)
	return nil
}

func (p *fakeProcess) die(err error) {
	p.once.Do(func() {
		p.exitErr = err
		close(p.exited)
	})
}

// fakeRunner hands out fakeProcesses and records what versions it started (by
// resolving the current symlink through the store).
type fakeRunner struct {
	mu      sync.Mutex
	store   *PayloadStore
	started []string
	procs   []*fakeProcess
	onStart func(version string, p *fakeProcess) // hook to script behaviour
}

func (r *fakeRunner) Start(_ context.Context, binPath string) (PayloadProcess, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	version := r.store.versionOf(binPath)
	p := newFakeProcess(version)
	r.started = append(r.started, version)
	r.procs = append(r.procs, p)
	if r.onStart != nil {
		r.onStart(version, p)
	}
	return p, nil
}

func (r *fakeRunner) startedVersions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.started...)
}

// fakeHealth reports which versions are considered healthy; unhealthy ones block
// until ctx (deadline) fires.
type fakeHealth struct {
	healthy map[string]bool
}

func (h *fakeHealth) WaitHealthy(ctx context.Context, version string) error {
	if h.healthy[version] {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func mustStageActivate(t *testing.T, s *PayloadStore, version, content string) {
	t.Helper()
	if _, err := s.Stage(version, strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(version); err != nil {
		t.Fatal(err)
	}
}

func newTestLauncher(t *testing.T, s *PayloadStore, r *fakeRunner, h *fakeHealth, pendingPath string) *Launcher {
	t.Helper()
	return NewLauncher(LauncherConfig{
		Store:             s,
		Runner:            r,
		Health:            h,
		Logger:            testLogger(t),
		HealthDeadline:    150 * time.Millisecond,
		PollInterval:      10 * time.Millisecond,
		PendingUpdatePath: pendingPath,
	})
}

// A healthy version supervised until shutdown starts exactly once and stops on
// context cancel.
func TestLauncher_HealthyRunsUntilShutdown(t *testing.T) {
	s := newTestStore(t)
	mustStageActivate(t, s, "v1", "V1")
	r := &fakeRunner{store: s}
	h := &fakeHealth{healthy: map[string]bool{"v1": true}}
	l := newTestLauncher(t, s, r, h, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	// Let it reach steady state, then shut down.
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if got := r.startedVersions(); len(got) != 1 || got[0] != "v1" {
		t.Errorf("started versions = %v, want [v1]", got)
	}
}

// A version that never commits health (misses the deadline) is quarantined and
// rolled back to the previous good version, which is then started.
func TestLauncher_UnhealthyRollsBackAndQuarantines(t *testing.T) {
	s := newTestStore(t)
	mustStageActivate(t, s, "good", "GOOD")
	mustStageActivate(t, s, "bad", "BAD") // current=bad, previous=good
	r := &fakeRunner{store: s}
	h := &fakeHealth{healthy: map[string]bool{"good": true}} // bad never healthy
	l := newTestLauncher(t, s, r, h, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	// bad misses its 150ms deadline → rollback to good → good runs healthy.
	time.Sleep(400 * time.Millisecond)
	cancel()
	<-done

	if !s.IsQuarantined("bad") {
		t.Error("bad version was not quarantined")
	}
	_, curVer, _ := s.Current()
	if curVer != "good" {
		t.Errorf("current after rollback = %q, want good", curVer)
	}
	started := r.startedVersions()
	if len(started) < 2 || started[0] != "bad" || started[len(started)-1] != "good" {
		t.Errorf("started versions = %v, want [bad ... good]", started)
	}
}

// A version that exits before committing health is treated as bad (rolled back),
// not merely restarted.
func TestLauncher_ExitBeforeHealthIsBad(t *testing.T) {
	s := newTestStore(t)
	mustStageActivate(t, s, "good", "GOOD")
	mustStageActivate(t, s, "crasher", "CRASH")
	r := &fakeRunner{store: s}
	r.onStart = func(version string, p *fakeProcess) {
		if version == "crasher" {
			// Exit almost immediately, before the health deadline.
			go func() { time.Sleep(20 * time.Millisecond); p.die(errors.New("boom")) }()
		}
	}
	h := &fakeHealth{healthy: map[string]bool{"good": true}}
	l := newTestLauncher(t, s, r, h, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	if !s.IsQuarantined("crasher") {
		t.Error("crasher was not quarantined after exiting before health")
	}
	if _, curVer, _ := s.Current(); curVer != "good" {
		t.Errorf("current = %q, want good", curVer)
	}
}

// A pending-update marker restarts the child onto the newly-activated current
// version.
func TestLauncher_PendingUpdateRestartsOntoNewVersion(t *testing.T) {
	s := newTestStore(t)
	mustStageActivate(t, s, "v1", "V1")
	// Pre-stage v2 but do NOT activate yet; the "update flow" activates it and
	// touches the marker mid-run.
	if _, err := s.Stage("v2", strings.NewReader("V2")); err != nil {
		t.Fatal(err)
	}
	pending := s.Root() + "/pending-update"
	r := &fakeRunner{store: s}
	h := &fakeHealth{healthy: map[string]bool{"v1": true, "v2": true}}
	l := newTestLauncher(t, s, r, h, pending)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	// Wait for v1 to be healthy & in steady state, then simulate the update flow.
	time.Sleep(60 * time.Millisecond)
	if err := s.Activate("v2"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pending, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// Give the launcher time to consume the marker and restart onto v2.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := r.startedVersions()
		if len(got) >= 2 && got[len(got)-1] == "v2" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	got := r.startedVersions()
	if len(got) < 2 || got[0] != "v1" || got[len(got)-1] != "v2" {
		t.Errorf("started versions = %v, want [v1 ... v2]", got)
	}
	// Marker consumed.
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Errorf("pending-update marker not consumed")
	}
}

// No current version is an unrecoverable start error.
func TestLauncher_NoCurrentIsError(t *testing.T) {
	s := newTestStore(t)
	r := &fakeRunner{store: s}
	h := &fakeHealth{healthy: map[string]bool{}}
	l := newTestLauncher(t, s, r, h, "")
	err := l.Run(context.Background())
	if err == nil {
		t.Fatal("Run with no current version should error")
	}
}

// A bad version with no last-known-good is unrecoverable.
func TestLauncher_BadVersionNoPreviousIsFatal(t *testing.T) {
	s := newTestStore(t)
	mustStageActivate(t, s, "onlybad", "BAD") // no previous
	r := &fakeRunner{store: s}
	h := &fakeHealth{healthy: map[string]bool{}} // never healthy
	l := newTestLauncher(t, s, r, h, "")
	err := l.Run(context.Background())
	if err == nil {
		t.Fatal("bad version with no previous should be fatal")
	}
}
