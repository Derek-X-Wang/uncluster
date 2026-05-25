package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// TestDeleteAgent_Returns204 verifies DELETE /v1/agents/{id} returns 204.
func TestDeleteAgent_Returns204(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "rev.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "rev-box")

	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/agents/"+agentID, nil)
	req.Header.Set("Authorization", "Bearer "+cliTok)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status=%d, want 204", resp.StatusCode)
	}
}

// TestDeleteAgent_ByName verifies DELETE /v1/agents/{name} also works.
func TestDeleteAgent_ByName(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "revn.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	_, _ = mintAgentAndToken(t, st, ts, "rev-box-byname")

	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/agents/rev-box-byname", nil)
	req.Header.Set("Authorization", "Bearer "+cliTok)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete by name: status=%d, want 204", resp.StatusCode)
	}
}

// TestRevokedAgent_Heartbeat_Returns410 verifies that after DELETE, the agent's
// next heartbeat receives 410 Gone with reason=node_revoked.
func TestRevokedAgent_Heartbeat_Returns410(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "hb410.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	agentID, agentTok := mintAgentAndToken(t, st, ts, "hb410-box")

	// Revoke the agent.
	delReq, _ := http.NewRequest("DELETE", ts.URL+"/v1/agents/"+agentID, nil)
	delReq.Header.Set("Authorization", "Bearer "+cliTok)
	delResp, _ := http.DefaultClient.Do(delReq)
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status=%d", delResp.StatusCode)
	}

	// Agent tries to heartbeat.
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v0.0.1",
		ObservedAt:   1000,
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+agentTok)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, _ := http.DefaultClient.Do(hbReq)
	defer hbResp.Body.Close()

	if hbResp.StatusCode != http.StatusGone {
		t.Fatalf("revoked heartbeat: status=%d, want 410", hbResp.StatusCode)
	}

	var revResp api.RevokedResponse
	json.NewDecoder(hbResp.Body).Decode(&revResp)
	if revResp.Reason != "node_revoked" {
		t.Errorf("reason = %q, want node_revoked", revResp.Reason)
	}
}

// TestSetAgent_FailClosedAfter verifies PATCH /v1/agents/{id} sets fail_closed_after.
func TestSetAgent_FailClosedAfter(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "fca.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	agentID, _ := mintAgentAndToken(t, st, ts, "fca-box")

	secs := int64(3600)
	patchBody, _ := json.Marshal(map[string]any{"fail_closed_after": secs})
	patchReq, _ := http.NewRequest("PATCH", ts.URL+"/v1/agents/"+agentID, bytes.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+cliTok)
	patchReq.Header.Set("Content-Type", "application/json")
	patchResp, _ := http.DefaultClient.Do(patchReq)
	patchResp.Body.Close()

	if patchResp.StatusCode != http.StatusNoContent {
		t.Fatalf("patch: status=%d, want 204", patchResp.StatusCode)
	}

	// Verify GET returns the updated value.
	getReq, _ := http.NewRequest("GET", ts.URL+"/v1/agents/"+agentID, nil)
	getReq.Header.Set("Authorization", "Bearer "+cliTok)
	getResp, _ := http.DefaultClient.Do(getReq)
	defer getResp.Body.Close()
	var detail api.AgentDetail
	json.NewDecoder(getResp.Body).Decode(&detail)
	if detail.FailClosedAfter == nil || *detail.FailClosedAfter != secs {
		t.Errorf("fail_closed_after = %v, want %d", detail.FailClosedAfter, secs)
	}
}

// TestHeartbeat_IncludesFailClosedAfter verifies the V2 heartbeat response
// includes fail_closed_after when set on the agent.
func TestHeartbeat_IncludesFailClosedAfter(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "hbfca.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	agentID, agentTok := mintAgentAndToken(t, st, ts, "hbfca-box")

	// Set fail-closed-after.
	secs := int64(1800)
	patchBody, _ := json.Marshal(map[string]any{"fail_closed_after": secs})
	patchReq, _ := http.NewRequest("PATCH", ts.URL+"/v1/agents/"+agentID, bytes.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+cliTok)
	patchReq.Header.Set("Content-Type", "application/json")
	pr, _ := http.DefaultClient.Do(patchReq)
	pr.Body.Close()

	// Heartbeat.
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v0.0.1",
		ObservedAt:   2000,
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+agentTok)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, _ := http.DefaultClient.Do(hbReq)
	defer hbResp.Body.Close()

	if hbResp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: status=%d", hbResp.StatusCode)
	}
	var hbr api.V2HeartbeatResponse
	json.NewDecoder(hbResp.Body).Decode(&hbr)
	if hbr.FailClosedAfter == nil || *hbr.FailClosedAfter != secs {
		t.Errorf("fail_closed_after = %v, want %d", hbr.FailClosedAfter, secs)
	}
}

// TestListAgents_ReturnsRegistered verifies GET /v1/agents lists enrolled agents.
func TestListAgents_ReturnsRegistered(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "list.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	mintAgentAndToken(t, st, ts, "list-box-1")
	mintAgentAndToken(t, st, ts, "list-box-2")

	req, _ := http.NewRequest("GET", ts.URL+"/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+cliTok)
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status=%d", resp.StatusCode)
	}
	var agents []api.AgentDetail
	json.NewDecoder(resp.Body).Decode(&agents)
	if len(agents) != 2 {
		t.Errorf("want 2 agents, got %d", len(agents))
	}
}
