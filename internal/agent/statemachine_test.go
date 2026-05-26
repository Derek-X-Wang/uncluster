package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)


// TestErrRevoked_IsDistinctFromErrUnauthorized verifies the two sentinel errors
// are distinct values.
func TestErrRevoked_IsDistinctFromErrUnauthorized(t *testing.T) {
	if errors.Is(ErrRevoked, ErrUnauthorized) {
		t.Error("ErrRevoked must not match ErrUnauthorized")
	}
	if errors.Is(ErrUnauthorized, ErrRevoked) {
		t.Error("ErrUnauthorized must not match ErrRevoked")
	}
}

// TestServerClient_Do_Returns410AsErrRevoked verifies that a 410 response
// triggers ErrRevoked.
func TestServerClient_Do_Returns410AsErrRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	c := NewServerClient(srv.URL, "tok")
	_, err := c.do(context.Background(), "POST", "/v1/agent/heartbeat", nil, nil)
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("expected ErrRevoked, got: %v", err)
	}
}

// TestServerClient_Do_Returns401AsErrUnauthorized verifies that a 401 response
// triggers ErrUnauthorized (not ErrRevoked).
func TestServerClient_Do_Returns401AsErrUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewServerClient(srv.URL, "tok")
	_, err := c.do(context.Background(), "POST", "/v1/agent/heartbeat", nil, nil)
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got: %v", err)
	}
	if errors.Is(err, ErrRevoked) {
		t.Error("401 should not produce ErrRevoked")
	}
}

// TestOnRevoked_WipesPrincipals verifies that onRevoked() removes all files
// from the principals directory.
func TestOnRevoked_WipesPrincipals(t *testing.T) {
	// Use two distinct dirs to model the real install layout (#46): config
	// dir holds agent.toml + the .deprovisioned marker; principals dir lives
	// in /etc/ssh/auth_principals. Pre-fix the marker was incorrectly
	// derived from CAPubkey's dir; this test pins the new behaviour.
	configDir := t.TempDir()
	principalsDir := t.TempDir()
	for _, name := range []string{"alice", "bob", "derek"} {
		if err := os.WriteFile(filepath.Join(principalsDir, name), []byte("caller_123\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	a := &Agent{
		cfg: Config{
			ExpectedPaths: ExpectedPaths{
				PrincipalsDir: principalsDir,
				CAPubkey:      "/etc/ssh/uncluster_ca.pub", // different dir on purpose
			},
		},
		configPath: filepath.Join(configDir, "agent.toml"),
		logger:     testLogger(t),
	}

	err := a.onRevoked()
	if !errors.Is(err, ErrDeprovisioned) {
		t.Errorf("expected ErrDeprovisioned, got: %v", err)
	}

	// All principal files should be gone.
	entries, _ := os.ReadDir(principalsDir)
	for _, e := range entries {
		if !e.IsDir() {
			t.Errorf("unexpected file after revoke in principals dir: %s", e.Name())
		}
	}

	// .deprovisioned marker should exist NEXT TO agent.toml (the config dir),
	// NOT next to the CA pubkey or in the principals dir.
	marker := filepath.Join(configDir, ".deprovisioned")
	if _, err := os.Stat(marker); os.IsNotExist(err) {
		t.Errorf(".deprovisioned marker not at %s (this is the #46 regression)", marker)
	}
	// And NOT next to the CA pubkey.
	if _, err := os.Stat("/etc/ssh/.deprovisioned"); err == nil {
		t.Errorf(".deprovisioned marker leaked to /etc/ssh — the #46 bug")
	}
	// And NOT in the principals dir.
	if _, err := os.Stat(filepath.Join(principalsDir, ".deprovisioned")); err == nil {
		t.Errorf(".deprovisioned marker leaked into principals dir")
	}
}

// TestOnRevoked_WritesDeprovisionedMarker verifies the marker content lands
// at the config-dir location.
func TestOnRevoked_WritesDeprovisionedMarker(t *testing.T) {
	configDir := t.TempDir()
	principalsDir := t.TempDir()
	a := &Agent{
		cfg: Config{
			ExpectedPaths: ExpectedPaths{
				PrincipalsDir: principalsDir,
				CAPubkey:      "/etc/ssh/uncluster_ca.pub",
			},
		},
		configPath: filepath.Join(configDir, "agent.toml"),
		logger:     testLogger(t),
	}
	_ = a.onRevoked()

	content, err := os.ReadFile(filepath.Join(configDir, ".deprovisioned"))
	if err != nil {
		t.Fatalf("marker not readable at config dir: %v", err)
	}
	if !strings.Contains(string(content), "deprovisioned") {
		t.Errorf("marker content unexpected: %q", content)
	}
}

// TestCheckFailClosed_WipesWhenElapsed verifies that checkFailClosed applies
// an empty policy when fail_closed_after has elapsed.
func TestCheckFailClosed_WipesWhenElapsed(t *testing.T) {
	dir := t.TempDir()
	// Write a principal file so we can verify it gets wiped.
	if err := os.WriteFile(filepath.Join(dir, "alice"), []byte("caller_123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Agent{
		cfg: Config{
			ExpectedPaths: ExpectedPaths{PrincipalsDir: dir},
		},
		logger: testLogger(t),
	}
	a.applyCh = make(chan applyRequest, 1)
	// Consumer goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for req := range a.applyCh {
			a.runApplyPolicy(req.snapshot)
		}
	}()

	secs := int64(1)
	a.fcaMu.Lock()
	a.failClosedAfterSec = &secs
	a.lastHeartbeatOK = time.Now().Add(-5 * time.Second) // well past the 1s threshold
	a.fcaMu.Unlock()

	a.checkFailClosed()

	// Give the apply goroutine time to process.
	time.Sleep(50 * time.Millisecond)
	close(a.applyCh)
	<-done

	// The principals file should be gone (empty policy applied).
	if _, err := os.Stat(filepath.Join(dir, "alice")); !os.IsNotExist(err) {
		t.Error("alice principals file should have been wiped by fail-closed")
	}
}

// TestCheckFailClosed_NoopWhenNotElapsed verifies that checkFailClosed does NOT
// wipe when the elapsed time is under fail_closed_after.
func TestCheckFailClosed_NoopWhenNotElapsed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bob"), []byte("caller_abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Agent{
		cfg: Config{
			ExpectedPaths: ExpectedPaths{PrincipalsDir: dir},
		},
		logger: testLogger(t),
	}

	secs := int64(3600) // 1 hour
	a.fcaMu.Lock()
	a.failClosedAfterSec = &secs
	a.lastHeartbeatOK = time.Now() // fresh heartbeat
	a.fcaMu.Unlock()

	a.checkFailClosed()

	// File should still be there.
	if _, err := os.Stat(filepath.Join(dir, "bob")); os.IsNotExist(err) {
		t.Error("bob principals file should NOT be wiped when under threshold")
	}
}

// TestCheckFailClosed_NoopWhenDisabled verifies no wipe when failClosedAfterSec is nil.
func TestCheckFailClosed_NoopWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "carol"), []byte("caller_xyz\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Agent{
		cfg: Config{
			ExpectedPaths: ExpectedPaths{PrincipalsDir: dir},
		},
		logger: testLogger(t),
	}
	// failClosedAfterSec is nil (disabled)

	a.checkFailClosed()

	if _, err := os.Stat(filepath.Join(dir, "carol")); os.IsNotExist(err) {
		t.Error("carol principals file should NOT be wiped when fail-closed disabled")
	}
}

// TestHeartbeatOnceV2_UpdatesLastHeartbeatOK verifies that a successful V2
// heartbeat updates lastHeartbeatOK.
func TestHeartbeatOnceV2_UpdatesLastHeartbeatOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ack_ts":1,"server_time":2,"commands":[]}`))
	}))
	defer srv.Close()

	a := &Agent{
		cfg: Config{
			AgentID: "ag_test",
			ExpectedPaths: ExpectedPaths{PrincipalsDir: t.TempDir()},
		},
		client: NewServerClient(srv.URL, "tok"),
		logger: testLogger(t),
	}
	a.applyCh = make(chan applyRequest, 1)
	defer close(a.applyCh)

	before := time.Now()
	if err := a.heartbeatOnceV2(context.Background()); err != nil {
		t.Fatalf("heartbeatOnceV2: %v", err)
	}

	a.fcaMu.Lock()
	lastOK := a.lastHeartbeatOK
	a.fcaMu.Unlock()

	if lastOK.Before(before) {
		t.Errorf("lastHeartbeatOK not updated: %v", lastOK)
	}
}

// TestHeartbeatOnceV2_SetsFailClosedAfterFromResponse verifies the agent
// reads fail_closed_after from the heartbeat response.
func TestHeartbeatOnceV2_SetsFailClosedAfterFromResponse(t *testing.T) {
	secs := int64(900)
	fcaJSON := `{"ack_ts":1,"server_time":2,"commands":[],"fail_closed_after":900}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fcaJSON))
	}))
	defer srv.Close()

	a := &Agent{
		cfg: Config{
			AgentID: "ag_test",
			ExpectedPaths: ExpectedPaths{PrincipalsDir: t.TempDir()},
		},
		client: NewServerClient(srv.URL, "tok"),
		logger: testLogger(t),
	}
	a.applyCh = make(chan applyRequest, 1)
	defer close(a.applyCh)

	if err := a.heartbeatOnceV2(context.Background()); err != nil {
		t.Fatalf("heartbeatOnceV2: %v", err)
	}

	a.fcaMu.Lock()
	fca := a.failClosedAfterSec
	a.fcaMu.Unlock()

	if fca == nil || *fca != secs {
		t.Errorf("failClosedAfterSec = %v, want %d", fca, secs)
	}
}

// testLogger returns the default slog logger for use in tests.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.Default()
}
