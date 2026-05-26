package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRun_410Deprovision_EndToEnd exercises the full 410-Gone flow (#46):
//  1. Control plane returns 410 on the first heartbeat.
//  2. Agent goes through onRevoked: principals wiped, marker written.
//  3. Run() returns ErrDeprovisioned.
//  4. The marker is at the configPath's dir (not at ExpectedPaths.CAPubkey,
//     which was the #46 bug).
//
// Pre-fix the marker landed in /etc/ssh (CAPubkey's dir) and the supervisor
// + CLI restart flow never noticed it → supervisor flap loop.
func TestRun_410Deprovision_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every heartbeat returns 410 → ErrRevoked → onRevoked.
		w.WriteHeader(http.StatusGone)
	}))
	t.Cleanup(srv.Close)

	configDir := t.TempDir()
	principalsDir := t.TempDir()
	// Plant a principals file so we can confirm the wipe.
	if err := os.WriteFile(filepath.Join(principalsDir, "derek"),
		[]byte("caller_abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "agent.toml")

	a := New(Config{
		Server: srv.URL,
		AgentToken: "uct_agent_0123456789ABCDEF_" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		AgentID: "ag_test",
		ExpectedPaths: ExpectedPaths{
			PrincipalsDir: principalsDir,
			CAPubkey:      "/etc/ssh/uncluster_ca.pub", // intentionally elsewhere
		},
	}, testLogger(t)).WithConfigPath(configPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := a.Run(ctx)
	if err == nil || err.Error() != ErrDeprovisioned.Error() {
		t.Fatalf("Run after 410: got err=%v, want ErrDeprovisioned", err)
	}

	// Marker MUST be next to agent.toml.
	wantMarker := filepath.Join(configDir, ".deprovisioned")
	if _, err := os.Stat(wantMarker); err != nil {
		t.Errorf("marker not at %s: %v (regression of #46)", wantMarker, err)
	}
	// Marker MUST NOT be in CAPubkey's dir.
	if _, err := os.Stat("/etc/ssh/.deprovisioned"); err == nil {
		t.Errorf("marker leaked to /etc/ssh — #46 regression")
	}
	// Principals must be wiped.
	entries, _ := os.ReadDir(principalsDir)
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("principals not wiped after 410: %v", names)
	}

	// DeprovisionedMarkerPath() exposes the same path the CLI startup check
	// should consult; verify it matches.
	if got := a.DeprovisionedMarkerPath(); got != wantMarker {
		t.Errorf("DeprovisionedMarkerPath = %q, want %q", got, wantMarker)
	}
}

// TestDeprovisionedMarkerPath_Resolution covers the helper independently:
// when configPath is set it derives sibling-of-agent.toml; when empty it
// falls back to the default config path.
func TestDeprovisionedMarkerPath_Resolution(t *testing.T) {
	t.Run("with configPath", func(t *testing.T) {
		got := deprovisionedMarkerPath("/tmp/x/agent.toml")
		if got != "/tmp/x/.deprovisioned" {
			t.Errorf("got %q, want /tmp/x/.deprovisioned", got)
		}
	})
	t.Run("without configPath uses default", func(t *testing.T) {
		// Tolerate either OS-default or last-resort cwd-relative paths.
		got := deprovisionedMarkerPath("")
		if got == "" {
			t.Error("empty marker path")
		}
		if filepath.Base(got) != ".deprovisioned" {
			t.Errorf("marker basename = %q, want .deprovisioned", filepath.Base(got))
		}
	})
}
