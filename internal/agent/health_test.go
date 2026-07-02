package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// heartbeatCaptureAgent spins up an httptest control plane that records the
// health slice of the heartbeat it receives, and returns a wired Agent whose
// health provider is `hp`. The returned func yields the captured health.
func heartbeatCaptureAgent(t *testing.T, hp HealthProvider) (*Agent, func() []api.AgentHealthCheck) {
	t.Helper()
	var gotHealth []api.AgentHealthCheck
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.V2HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotHealth = req.Health
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ack_ts":1,"server_time":2,"commands":[]}`))
	}))
	t.Cleanup(srv.Close)

	a := &Agent{
		cfg: Config{
			AgentID:       "ag_test",
			ExpectedPaths: ExpectedPaths{PrincipalsDir: t.TempDir()},
		},
		client:         NewServerClient(srv.URL, "tok"),
		logger:         testLogger(t),
		healthProvider: hp,
	}
	a.applyCh = make(chan applyRequest, 1)
	t.Cleanup(func() { close(a.applyCh) })
	return a, func() []api.AgentHealthCheck { return gotHealth }
}

// assertSyntheticFailCheck asserts that health is exactly one FAILED check from
// the health_provider component whose message contains wantMsgSubstr.
func assertSyntheticFailCheck(t *testing.T, health []api.AgentHealthCheck, wantMsgSubstr string) {
	t.Helper()
	if len(health) != 1 {
		t.Fatalf("health = %+v, want exactly one synthetic check", health)
	}
	c := health[0]
	if c.Component != "health_provider" || c.Check != "collect" || c.State != "fail" {
		t.Errorf("check = {comp=%q check=%q state=%q}, want health_provider/collect/fail", c.Component, c.Check, c.State)
	}
	if c.ErrorCode == nil || *c.ErrorCode != "provider_failure" {
		t.Errorf("error_code = %v, want provider_failure", c.ErrorCode)
	}
	if c.Message == nil || !strings.Contains(*c.Message, wantMsgSubstr) {
		t.Errorf("message = %v, want substring %q", c.Message, wantMsgSubstr)
	}
}

// TestHeartbeatOnceV2_ProviderErrorBecomesFailedCheck drives an erroring health
// provider through the heartbeat path and asserts the error surfaces as a
// synthetic FAILED check on the wire (not an empty health slice).
func TestHeartbeatOnceV2_ProviderErrorBecomesFailedCheck(t *testing.T) {
	a, health := heartbeatCaptureAgent(t, func(context.Context) ([]api.AgentHealthCheck, error) {
		return nil, errors.New("doctor exploded")
	})

	if err := a.heartbeatOnceV2(context.Background()); err != nil {
		t.Fatalf("heartbeatOnceV2: %v", err)
	}
	assertSyntheticFailCheck(t, health(), "doctor exploded")
}

// TestHeartbeatOnceV2_ProviderPanicBecomesFailedCheck drives a panicking
// provider through the heartbeat path: the panic is recovered (heartbeat still
// succeeds) and converted to the same synthetic FAILED check — no silent recover.
func TestHeartbeatOnceV2_ProviderPanicBecomesFailedCheck(t *testing.T) {
	a, health := heartbeatCaptureAgent(t, func(context.Context) ([]api.AgentHealthCheck, error) {
		panic("nil map write in doctor")
	})

	if err := a.heartbeatOnceV2(context.Background()); err != nil {
		t.Fatalf("heartbeatOnceV2 must survive a panicking provider: %v", err)
	}
	assertSyntheticFailCheck(t, health(), "nil map write in doctor")
}

// TestHeartbeatOnceV2_HealthyProviderPassesThrough confirms a well-behaved
// provider's checks travel the wire unchanged (no synthetic wrapping).
func TestHeartbeatOnceV2_HealthyProviderPassesThrough(t *testing.T) {
	want := []api.AgentHealthCheck{
		{Component: "sshd", Check: "running", State: "ok"},
		{Component: "ca_pubkey", Check: "present", State: "ok"},
	}
	a, health := heartbeatCaptureAgent(t, func(context.Context) ([]api.AgentHealthCheck, error) {
		return want, nil
	})

	if err := a.heartbeatOnceV2(context.Background()); err != nil {
		t.Fatalf("heartbeatOnceV2: %v", err)
	}
	got := health()
	if len(got) != 2 || got[0].Component != "sshd" || got[1].Component != "ca_pubkey" {
		t.Fatalf("health = %+v, want the provider's two checks unchanged", got)
	}
	for _, c := range got {
		if c.State != "ok" {
			t.Errorf("healthy check %q reported state %q, want ok", c.Component, c.State)
		}
	}
}

// TestCollectHealth_NilProviderReturnsNil confirms that with no provider wired
// there is no synthetic check — an empty health slice is correct because there
// is no truth source to have failed.
func TestCollectHealth_NilProviderReturnsNil(t *testing.T) {
	a := &Agent{logger: testLogger(t)}
	if got := a.collectHealth(context.Background()); got != nil {
		t.Fatalf("collectHealth with nil provider = %+v, want nil", got)
	}
}
