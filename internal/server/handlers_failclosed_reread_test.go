package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// flakeyGetAgentStore wraps a real store and fails the Nth GetAgent call
// based on calls.Load(). The auth middleware calls GetAgent for the agent
// token first, and then the heartbeat handler re-reads. We want only the
// SECOND read to fail so the auth pre-read still succeeds.
type flakeyGetAgentStore struct {
	store.Store
	calls atomic.Int64
	// FailCallN: the 1-indexed call number to fail. Set to 2 to fail the
	// heartbeat-handler re-read while letting the auth-time read succeed.
	FailCallN int64
}

func (f *flakeyGetAgentStore) GetAgent(ctx context.Context, id string) (store.Agent, error) {
	n := f.calls.Add(1)
	if n == f.FailCallN {
		return store.Agent{}, errors.New("simulated SQLite busy_timeout exceeded")
	}
	return f.Store.GetAgent(ctx, id)
}

// TestHeartbeat_GetAgentRereadFails_FallsBackToAuthValue proves the fix for
// #47: if the re-read GetAgent fails the response carries the agent's
// fail_closed_after from the auth-time row (not nil from a zero-value
// Agent). Pre-fix the response field was always nil after a re-read failure,
// briefly flipping the Agent into lenient (no-fail-closed) mode.
func TestHeartbeat_GetAgentRereadFails_FallsBackToAuthValue(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "fcrr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	wrapped := &flakeyGetAgentStore{Store: st, FailCallN: -1} // disabled initially
	srv := server.New(server.Config{Store: wrapped})
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	agentID, agentTok := mintAgentAndToken(t, st, ts, "fcrr-agent")

	// Operator sets fail_closed_after=3600s on the agent.
	secs := int64(3600)
	patchBody, _ := json.Marshal(map[string]any{"fail_closed_after": secs})
	patchReq, _ := http.NewRequest("PATCH", ts.URL+"/v1/agents/"+agentID,
		bytes.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+cliTok)
	patchReq.Header.Set("Content-Type", "application/json")
	pr, _ := http.DefaultClient.Do(patchReq)
	pr.Body.Close()

	// Reset call counter and arm the wrapper to fail the next GetAgent that
	// is NOT the auth pre-read. The auth middleware calls GetAgent once,
	// then the heartbeat handler re-reads. So FailCallN = 2.
	wrapped.calls.Store(0)
	wrapped.FailCallN = 2

	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v0.0.1",
		ObservedAt:   1000,
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat",
		bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+agentTok)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, err := http.DefaultClient.Do(hbReq)
	if err != nil {
		t.Fatal(err)
	}
	defer hbResp.Body.Close()
	if hbResp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: status=%d", hbResp.StatusCode)
	}

	var hbr api.V2HeartbeatResponse
	if err := json.NewDecoder(hbResp.Body).Decode(&hbr); err != nil {
		t.Fatal(err)
	}

	// Pre-fix this would be nil (re-read returned zero Agent, FailClosedAfter
	// was nil). With the fix the auth-time value carries through.
	if hbr.FailClosedAfter == nil {
		t.Fatalf("FailClosedAfter is nil after re-read failure; expected fallback to auth-time value (%d)", secs)
	}
	if *hbr.FailClosedAfter != secs {
		t.Errorf("FailClosedAfter = %d, want %d (auth-time value)",
			*hbr.FailClosedAfter, secs)
	}
}
