package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func newAuthTestSetup(t *testing.T) (*httptest.Server, store.Store, token.Token) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	tok, _ := token.Generate(token.KindCaller)
	hash, _ := token.HashSecret(tok.Secret)
	// Poke the token directly into the store with our desired ID.
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		tok.ID, store.TokenCaller, nil, hash, "test"); err != nil {
		t.Fatal(err)
	}

	srv := server.New(server.Config{Store: st})
	// Mount a protected probe route for testing.
	probe := server.MountProbeRoute(srv)
	ts := httptest.NewServer(probe)
	t.Cleanup(ts.Close)
	return ts, st, tok
}

func TestAuthMiddleware_AcceptsValidToken(t *testing.T) {
	ts, _, tok := newAuthTestSetup(t)
	req, _ := http.NewRequest("GET", ts.URL+"/__probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_RejectsMissing(t *testing.T) {
	ts, _, _ := newAuthTestSetup(t)
	resp, _ := http.Get(ts.URL + "/__probe")
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_RejectsWrongSecret(t *testing.T) {
	ts, _, tok := newAuthTestSetup(t)
	bad := "uct_caller_" + tok.ID + "_" + strings("A", 52) // wrong secret
	req, _ := http.NewRequest("GET", ts.URL+"/__probe", nil)
	req.Header.Set("Authorization", "Bearer "+bad)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func strings(c string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += c
	}
	return out
}

// TestRevokedAgentToken_Heartbeat_Returns401 is the integration test for
// ACCEPTANCE.md §44: revoking the agent's token via DELETE /v1/tokens/{id}
// (not DELETE /v1/agents/{id}) must make the next heartbeat return 401, not
// 410, and must NOT trigger deprovision or principal wipe.
//
// Without the fix, the middleware skipped the revoked_at check for TokenAgent
// and let the revoked token authenticate indefinitely.
func TestRevokedAgentToken_Heartbeat_Returns401(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "tokrev.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Seed a Caller token for operator requests.
	cliTok, _ := token.Generate(token.KindCaller)
	cliHash, _ := token.HashSecret(cliTok.Secret)
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		cliTok.ID, store.TokenCaller, nil, cliHash, "op"); err != nil {
		t.Fatal(err)
	}

	// Register an Agent via the register endpoint (mints a join token internally).
	agentID, agentTokStr := mintAgentAndToken(t, st, ts, "tokrev-agent")

	// Parse the agent token to extract its ID for the revoke call.
	parsedAgentTok, err := token.Parse(agentTokStr)
	if err != nil {
		t.Fatalf("parse agent token: %v", err)
	}
	agentTokenID := parsedAgentTok.ID

	// Verify the heartbeat works before token revocation.
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v0.0.1",
		ObservedAt:   1000,
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+agentTokStr)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, _ := http.DefaultClient.Do(hbReq)
	hbResp.Body.Close()
	if hbResp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke heartbeat: status=%d, want 200", hbResp.StatusCode)
	}

	// Revoke the agent's token via DELETE /v1/tokens/{id}.
	// This path only sets tokens.revoked_at — it does NOT touch agents.status.
	delReq, _ := http.NewRequest("DELETE", ts.URL+"/v1/tokens/"+agentTokenID, nil)
	delReq.Header.Set("Authorization", "Bearer "+cliTok.String())
	delResp, _ := http.DefaultClient.Do(delReq)
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /v1/tokens/{id}: status=%d, want 204", delResp.StatusCode)
	}

	// After token revocation, heartbeat must return 401 Unauthorized.
	// Before the fix it returned 200 (bypass bug). It must NOT return 410 Gone
	// (which would be deprovision — only triggered by DELETE /v1/agents/{id}).
	hbBody2, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v0.0.1",
		ObservedAt:   2000,
	})
	hbReq2, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody2))
	hbReq2.Header.Set("Authorization", "Bearer "+agentTokStr)
	hbReq2.Header.Set("Content-Type", "application/json")
	hbResp2, err := http.DefaultClient.Do(hbReq2)
	if err != nil {
		t.Fatal(err)
	}
	defer hbResp2.Body.Close()

	if hbResp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-token-revoke heartbeat: status=%d, want 401 (not 410 = deprovision, not 200 = bypass)",
			hbResp2.StatusCode)
	}

	// Confirm agent record is still enrolled — token revoke must NOT deprovision.
	ag, err := st.GetAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("GetAgent after token revoke: %v", err)
	}
	if ag.Status == store.AgentRevoked {
		t.Errorf("agent status = %q after token revoke; want enrolled (deprovision is separate path)", ag.Status)
	}
}
