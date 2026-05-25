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
	"github.com/derek-x-wang/uncluster/internal/token"
)

// seedCallerToken creates a caller token directly in the store and returns the
// plaintext token string (for Authorization header) and the token id.
func seedCallerToken(t *testing.T, st store.Store) (plaintext, id string) {
	t.Helper()
	tok, err := token.Generate(token.KindCaller)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := token.HashSecret(tok.Secret)
	row, err := st.CreateToken(context.Background(), store.NewTokenParams{
		ID:         tok.ID,
		Kind:       store.TokenCaller,
		SecretHash: hash,
		Label:      "test-caller",
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok.String(), row.ID
}

// TestACL_CreateListDelete exercises the full lifecycle of an ACL entry
// through the HTTP endpoints.
func TestACL_CreateListDelete(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "acl.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	callerPlaintext, callerID := seedCallerToken(t, st)
	_ = callerPlaintext

	// Register an agent to have a valid agent_id.
	jt := mintJoinToken(t, st)
	regBody, _ := json.Marshal(api.AgentRegisterRequest{JoinToken: jt, Name: "acl-box"})
	regResp, _ := http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(regBody))
	var reg api.AgentRegisterResponse
	json.NewDecoder(regResp.Body).Decode(&reg)
	regResp.Body.Close()
	agentID := reg.AgentID

	doRequest := func(method, path string, body any) *http.Response {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			json.NewEncoder(&buf).Encode(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, &buf)
		req.Header.Set("Authorization", "Bearer "+cliTok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	// POST /v1/acl — create
	createResp := doRequest("POST", "/v1/acl", api.CreateACLRequest{
		Caller:   callerID,
		Agent:    agentID,
		Username: "derek",
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create ACL: status=%d", createResp.StatusCode)
	}
	var entry api.ACLEntrySummary
	json.NewDecoder(createResp.Body).Decode(&entry)
	createResp.Body.Close()

	if entry.ID == "" {
		t.Error("entry.id empty")
	}
	if entry.CallerTokenID != callerID {
		t.Errorf("caller_token_id = %q, want %q", entry.CallerTokenID, callerID)
	}
	if entry.AgentID != agentID {
		t.Errorf("agent_id = %q, want %q", entry.AgentID, agentID)
	}
	if entry.Username != "derek" {
		t.Errorf("username = %q, want derek", entry.Username)
	}

	// GET /v1/acl?agent=<id> — list filtered
	listResp := doRequest("GET", "/v1/acl?agent="+agentID, nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list ACL: status=%d", listResp.StatusCode)
	}
	var entries []api.ACLEntrySummary
	json.NewDecoder(listResp.Body).Decode(&entries)
	listResp.Body.Close()
	if len(entries) != 1 || entries[0].ID != entry.ID {
		t.Errorf("list ACL: got %d entries", len(entries))
	}

	// DELETE /v1/acl/{id}
	delResp := doRequest("DELETE", "/v1/acl/"+entry.ID, nil)
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete ACL: status=%d", delResp.StatusCode)
	}
	delResp.Body.Close()

	// List again — should be empty.
	listResp2 := doRequest("GET", "/v1/acl?agent="+agentID, nil)
	var entries2 []api.ACLEntrySummary
	json.NewDecoder(listResp2.Body).Decode(&entries2)
	listResp2.Body.Close()
	if len(entries2) != 0 {
		t.Errorf("after delete: expected 0 entries, got %d", len(entries2))
	}
}

// TestACL_Idempotent verifies that re-granting the same (caller, agent, user)
// triple returns 201 with the same ACL id.
func TestACL_Idempotent(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "acl-idem.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	_, callerID := seedCallerToken(t, st)

	jt := mintJoinToken(t, st)
	regBody, _ := json.Marshal(api.AgentRegisterRequest{JoinToken: jt, Name: "idem-agent"})
	regResp, _ := http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(regBody))
	var reg api.AgentRegisterResponse
	json.NewDecoder(regResp.Body).Decode(&reg)
	regResp.Body.Close()

	doCreate := func() api.ACLEntrySummary {
		t.Helper()
		b, _ := json.Marshal(api.CreateACLRequest{Caller: callerID, Agent: reg.AgentID, Username: "alice"})
		req, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+cliTok)
		req.Header.Set("Content-Type", "application/json")
		resp, _ := http.DefaultClient.Do(req)
		var e api.ACLEntrySummary
		json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		return e
	}

	e1 := doCreate()
	e2 := doCreate()
	if e1.ID != e2.ID {
		t.Errorf("idempotent re-grant: id changed %s → %s", e1.ID, e2.ID)
	}
}

// TestV2Heartbeat_PolicyDelivered verifies that the V2 heartbeat returns
// a policy snapshot when the agent's applied_hash does not match the server's.
func TestV2Heartbeat_PolicyDelivered(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "pol.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	_, callerID := seedCallerToken(t, st)

	// Register agent.
	agentID, agentTok := mintAgentAndToken(t, st, ts, "pol-agent")

	// Grant ACL so the policy is non-empty.
	grantBody, _ := json.Marshal(api.CreateACLRequest{
		Caller:   callerID,
		Agent:    agentID,
		Username: "derek",
	})
	grantReq, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(grantBody))
	grantReq.Header.Set("Authorization", "Bearer "+cliTok)
	grantReq.Header.Set("Content-Type", "application/json")
	grantResp, _ := http.DefaultClient.Do(grantReq)
	if grantResp.StatusCode != http.StatusCreated {
		t.Fatalf("grant ACL: status=%d", grantResp.StatusCode)
	}
	grantResp.Body.Close()

	// Heartbeat with stale applied_hash → should receive policy.
	observedAt := int64(1735689600)
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v2.0.0",
		ObservedAt:   observedAt,
		PolicyState: api.AgentPolicyState{
			AppliedVersion:  0,
			AppliedHash:     "blake3:stale",
			LastApplyStatus: "ok",
		},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("heartbeat: status=%d", resp.StatusCode)
	}
	var hbResp api.V2HeartbeatResponse
	json.NewDecoder(resp.Body).Decode(&hbResp)
	resp.Body.Close()

	if hbResp.Policy == nil {
		t.Fatal("expected policy in response when applied_hash is stale")
	}
	if hbResp.Policy.Version != 1 {
		t.Errorf("policy.version = %d, want 1", hbResp.Policy.Version)
	}
	if hbResp.Policy.Hash == "" {
		t.Error("policy.hash should be non-empty")
	}
	if len(hbResp.Policy.Principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(hbResp.Policy.Principals))
	}
	if hbResp.Policy.Principals[0].Username != "derek" {
		t.Errorf("principal username = %q, want derek", hbResp.Policy.Principals[0].Username)
	}
	if len(hbResp.Policy.Principals[0].CallerTokenIDs) != 1 || hbResp.Policy.Principals[0].CallerTokenIDs[0] != callerID {
		t.Errorf("caller_token_ids = %v, want [%s]", hbResp.Policy.Principals[0].CallerTokenIDs, callerID)
	}
}

// TestV2Heartbeat_PolicyNotDeliveredWhenMatch verifies no policy is returned
// when the agent's applied_hash already matches the server's current hash.
func TestV2Heartbeat_PolicyNotDeliveredWhenMatch(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "pol-match.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cliTok := seedCLIToken(t, st)
	_, callerID := seedCallerToken(t, st)

	agentID, agentTok := mintAgentAndToken(t, st, ts, "pmatch-agent")

	// Grant ACL.
	grantBody, _ := json.Marshal(api.CreateACLRequest{Caller: callerID, Agent: agentID, Username: "alice"})
	grantReq, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(grantBody))
	grantReq.Header.Set("Authorization", "Bearer "+cliTok)
	grantReq.Header.Set("Content-Type", "application/json")
	grantResp, _ := http.DefaultClient.Do(grantReq)
	grantResp.Body.Close()

	// First heartbeat: get the policy hash.
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID: agentID, AgentVersion: "v2", ObservedAt: 1000,
		PolicyState: api.AgentPolicyState{AppliedHash: "blake3:stale"},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	var hbResp1 api.V2HeartbeatResponse
	json.NewDecoder(resp.Body).Decode(&hbResp1)
	resp.Body.Close()

	if hbResp1.Policy == nil {
		t.Fatal("expected policy on first heartbeat with stale hash")
	}
	currentHash := hbResp1.Policy.Hash

	// Second heartbeat: report the current hash → no policy in response.
	hbBody2, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID: agentID, AgentVersion: "v2", ObservedAt: 2000,
		PolicyState: api.AgentPolicyState{
			AppliedVersion:  1,
			AppliedHash:     currentHash,
			LastApplyStatus: "ok",
		},
	})
	req2, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody2))
	req2.Header.Set("Authorization", "Bearer "+agentTok)
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := http.DefaultClient.Do(req2)
	var hbResp2 api.V2HeartbeatResponse
	json.NewDecoder(resp2.Body).Decode(&hbResp2)
	resp2.Body.Close()

	if hbResp2.Policy != nil {
		t.Errorf("expected no policy when hashes match, got: %+v", hbResp2.Policy)
	}
}
