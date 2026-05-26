package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// TestHeartbeat_PersistsServerDesiredVersion proves the fix for #43: after a
// heartbeat round-trip in which the server returns a policy snapshot at
// version V, the agent_policy_state row's desired_version equals V. Pre-fix
// the handler stored req.PolicyState.DesiredVersion (always nil), so
// desired_version stayed at 0 forever and the "desired vs applied" gap
// invariant — the entire point of the version pair — could never fire.
func TestHeartbeat_PersistsServerDesiredVersion(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "dv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok, _ := seedCallerToken(t, st)
	agentID, agentTok := mintAgentAndToken(t, st, ts, "dv-agent")

	// Seed a Caller token whose ID will become an ACL principal.
	_, callerID := seedCallerToken(t, st)

	// Create an ACL row: this bumps the agent's policy version to 1.
	aclBody, _ := json.Marshal(api.CreateACLRequest{
		Caller:   callerID,
		Agent:    agentID,
		Username: "derek",
	})
	aclReq, _ := http.NewRequest("POST", ts.URL+"/v1/acl",
		bytes.NewReader(aclBody))
	aclReq.Header.Set("Authorization", "Bearer "+cliTok)
	aclReq.Header.Set("Content-Type", "application/json")
	aclResp, _ := http.DefaultClient.Do(aclReq)
	aclResp.Body.Close()
	if aclResp.StatusCode != http.StatusCreated && aclResp.StatusCode != http.StatusOK {
		t.Fatalf("create acl: status=%d", aclResp.StatusCode)
	}

	// Agent heartbeats reporting applied_hash="" (nothing applied yet) and
	// applied_version=0 / NO desired_version (Agents do not track that).
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v0.0.1",
		ObservedAt:   1000,
		PolicyState: api.AgentPolicyState{
			AppliedVersion:  0,
			AppliedHash:     "",
			LastApplyStatus: "ok",
		},
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
	if hbr.Policy == nil {
		t.Fatal("heartbeat response missing policy payload; should have sent v1")
	}
	pushedVersion := hbr.Policy.Version
	if pushedVersion < 1 {
		t.Fatalf("policy version pushed = %d, want >= 1", pushedVersion)
	}

	// Read agent_policy_state — desired_version must be the version the server
	// just pushed in the response (snap.Version), NOT the agent's nil report.
	ps, err := st.GetAgentPolicyState(context.Background(), agentID)
	if err != nil {
		t.Fatalf("GetAgentPolicyState: %v", err)
	}
	if ps.DesiredVersion == nil {
		t.Fatal("desired_version is nil; server should have recorded the snapshot version")
	}
	if *ps.DesiredVersion != pushedVersion {
		t.Errorf("persisted desired_version = %d, want %d (the version the server returned in this heartbeat)",
			*ps.DesiredVersion, pushedVersion)
	}

	// applied_version should reflect what the agent reported — still 0 in this
	// round-trip because the agent hasn't applied the pushed policy yet.
	if ps.AppliedVersion != 0 {
		t.Errorf("applied_version = %d, want 0 (agent has not yet applied)",
			ps.AppliedVersion)
	}

	// The desired-vs-applied gap is the entire point of the version pair;
	// confirm it is now observable.
	if *ps.DesiredVersion == ps.AppliedVersion {
		t.Errorf("desired_version (%d) == applied_version (%d); the gap that signals 'policy pushed but not applied' is invisible",
			*ps.DesiredVersion, ps.AppliedVersion)
	}
}

// TestHeartbeat_IgnoresAgentReportedDesiredVersion verifies the server does
// not let the Agent dictate desired_version. Even if a malicious or buggy
// Agent reports a wildly inflated desired_version, the persisted value must
// reflect the server's own snapshot version (CONTEXT.md: server is
// authoritative).
func TestHeartbeat_IgnoresAgentReportedDesiredVersion(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "dvign.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	agentID, agentTok := mintAgentAndToken(t, st, ts, "dvign-agent")
	// No ACL rows → snap.Version stays at 0; server should record 0 even if
	// the agent claims desired_version=9999.

	rogueDesired := int64(9999)
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v0.0.1",
		ObservedAt:   2000,
		PolicyState: api.AgentPolicyState{
			DesiredVersion:  &rogueDesired,
			AppliedVersion:  0,
			AppliedHash:     "",
			LastApplyStatus: "ok",
		},
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat",
		bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+agentTok)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, _ := http.DefaultClient.Do(hbReq)
	hbResp.Body.Close()

	ps, err := st.GetAgentPolicyState(context.Background(), agentID)
	if err != nil {
		t.Fatalf("GetAgentPolicyState: %v", err)
	}
	// snap.Version is 0 (no ACL rows); the store represents 0 as nil.
	if ps.DesiredVersion != nil && *ps.DesiredVersion != 0 {
		t.Errorf("desired_version = %v, want nil or 0 — agent-reported %d must be ignored",
			ps.DesiredVersion, rogueDesired)
	}
}
