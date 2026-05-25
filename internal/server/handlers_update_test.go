package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// TestSetUpdatePolicy_NoContent verifies POST /v1/server/update returns 204.
func TestSetUpdatePolicy_NoContent(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "upd.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())
	cliTok, _ := seedCallerToken(t, st)

	body, _ := json.Marshal(api.SetUpdatePolicyRequest{
		ExpectedVersion:   "v2.1.0",
		AssetURLTemplate:  "https://example.com/{os}/{arch}/uncluster-{version}",
		SHA256URLTemplate: "https://example.com/{os}/{arch}/uncluster-{version}.sha256",
		Force:             false,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/server/update", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cliTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

// TestGetUpdatePlan_Empty verifies GET /v1/agent/update-plan returns {} when no policy set.
func TestGetUpdatePlan_Empty(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "upde.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	// Enroll an agent to get an agent token.
	_, agentTok := mintAgentAndToken(t, st, ts, "upd-agent")

	req, _ := http.NewRequest("GET", ts.URL+"/v1/agent/update-plan", nil)
	req.Header.Set("Authorization", "Bearer "+agentTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var got api.UpdatePlanResponse
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.ExpectedVersion != "" {
		t.Errorf("want empty expected_version, got %q", got.ExpectedVersion)
	}
}

// TestGetUpdatePlan_ReturnsPolicy verifies GET /v1/agent/update-plan returns the set policy.
func TestGetUpdatePlan_ReturnsPolicy(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "updp.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())
	cliTok, _ := seedCallerToken(t, st)
	_, agentTok := mintAgentAndToken(t, st, ts, "upd-agent2")

	// Set policy via operator endpoint.
	body, _ := json.Marshal(api.SetUpdatePolicyRequest{
		ExpectedVersion:   "v2.5.0",
		AssetURLTemplate:  "https://dl.example.com/{os}/{arch}/uncluster-{version}",
		SHA256URLTemplate: "https://dl.example.com/{os}/{arch}/uncluster-{version}.sha256",
		Force:             true,
	})
	setReq, _ := http.NewRequest("POST", ts.URL+"/v1/server/update", bytes.NewReader(body))
	setReq.Header.Set("Authorization", "Bearer "+cliTok)
	setReq.Header.Set("Content-Type", "application/json")
	setResp, err := http.DefaultClient.Do(setReq)
	if err != nil {
		t.Fatal(err)
	}
	setResp.Body.Close()
	if setResp.StatusCode != http.StatusNoContent {
		t.Fatalf("set policy: want 204, got %d", setResp.StatusCode)
	}

	// Agent fetches update plan.
	getPlanReq, _ := http.NewRequest("GET", ts.URL+"/v1/agent/update-plan", nil)
	getPlanReq.Header.Set("Authorization", "Bearer "+agentTok)
	getPlanResp, err := http.DefaultClient.Do(getPlanReq)
	if err != nil {
		t.Fatal(err)
	}
	defer getPlanResp.Body.Close()
	if getPlanResp.StatusCode != http.StatusOK {
		t.Fatalf("get plan: want 200, got %d", getPlanResp.StatusCode)
	}
	var plan api.UpdatePlanResponse
	_ = json.NewDecoder(getPlanResp.Body).Decode(&plan)
	if plan.ExpectedVersion != "v2.5.0" {
		t.Errorf("expected_version = %q, want v2.5.0", plan.ExpectedVersion)
	}
	if !plan.Force {
		t.Error("force should be true")
	}
}

// TestHeartbeat_InjectsCheckUpdateCommand verifies that when the server has an
// update policy and the agent reports a different version, the heartbeat response
// includes a check_update command.
func TestHeartbeat_InjectsCheckUpdateCommand(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "hbupd.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())
	cliTok, _ := seedCallerToken(t, st)
	agentID, agentTok := mintAgentAndToken(t, st, ts, "upd-hb-agent")

	// Set update policy.
	body, _ := json.Marshal(api.SetUpdatePolicyRequest{ExpectedVersion: "v99.0.0"})
	setReq, _ := http.NewRequest("POST", ts.URL+"/v1/server/update", bytes.NewReader(body))
	setReq.Header.Set("Authorization", "Bearer "+cliTok)
	setReq.Header.Set("Content-Type", "application/json")
	setResp, err := http.DefaultClient.Do(setReq)
	if err != nil {
		t.Fatal(err)
	}
	setResp.Body.Close()

	// Agent heartbeats with a different version.
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v1.0.0", // different from v99.0.0
		ObservedAt:   time.Now().Unix(),
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+agentTok)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, err := http.DefaultClient.Do(hbReq)
	if err != nil {
		t.Fatal(err)
	}
	defer hbResp.Body.Close()
	if hbResp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: want 200, got %d", hbResp.StatusCode)
	}
	var hbOut api.V2HeartbeatResponse
	_ = json.NewDecoder(hbResp.Body).Decode(&hbOut)

	if len(hbOut.Commands) != 1 {
		t.Fatalf("want 1 command, got %d: %v", len(hbOut.Commands), hbOut.Commands)
	}
	// Commands is []any, re-marshal to inspect.
	cmdJSON, _ := json.Marshal(hbOut.Commands[0])
	var cmd api.CheckUpdateCommand
	_ = json.Unmarshal(cmdJSON, &cmd)
	if cmd.Type != "check_update" {
		t.Errorf("command type = %q, want check_update", cmd.Type)
	}
	if cmd.Version != "v99.0.0" {
		t.Errorf("command version = %q, want v99.0.0", cmd.Version)
	}
}

// TestHeartbeat_NoCommandWhenVersionMatches verifies no check_update when
// the agent is already on the expected version.
func TestHeartbeat_NoCommandWhenVersionMatches(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "hbmatch.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())
	cliTok, _ := seedCallerToken(t, st)
	agentID, agentTok := mintAgentAndToken(t, st, ts, "match-agent")

	// Set update policy.
	body, _ := json.Marshal(api.SetUpdatePolicyRequest{ExpectedVersion: "v2.0.0"})
	setReq, _ := http.NewRequest("POST", ts.URL+"/v1/server/update", bytes.NewReader(body))
	setReq.Header.Set("Authorization", "Bearer "+cliTok)
	setReq.Header.Set("Content-Type", "application/json")
	setResp, err := http.DefaultClient.Do(setReq)
	if err != nil {
		t.Fatal(err)
	}
	setResp.Body.Close()

	// Agent heartbeats with matching version.
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v2.0.0", // matches expected
		ObservedAt:   time.Now().Unix(),
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+agentTok)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, err := http.DefaultClient.Do(hbReq)
	if err != nil {
		t.Fatal(err)
	}
	defer hbResp.Body.Close()
	var hbOut api.V2HeartbeatResponse
	_ = json.NewDecoder(hbResp.Body).Decode(&hbOut)
	if len(hbOut.Commands) != 0 {
		t.Fatalf("want 0 commands, got %d: %v", len(hbOut.Commands), hbOut.Commands)
	}
}
