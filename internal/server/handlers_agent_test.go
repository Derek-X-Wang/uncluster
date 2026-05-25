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

func mintJoinToken(t *testing.T, st store.Store) string {
	t.Helper()
	jt, _ := token.Generate(token.KindJoin)
	hash, _ := token.HashSecret(jt.Secret)
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		jt.ID, store.TokenJoin, nil, hash, "join"); err != nil {
		t.Fatal(err)
	}
	return jt.String()
}

// TestAgentRegister_V2Response verifies the V2 enrollment response shape:
// agent_id, agent_token, ca_pubkey, expected_paths are all returned.
// Acceptance criteria: S2a §POST /v1/agent/register returns updated payload.
func TestAgentRegister_V2Response(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	defer st.Close()

	const testCAPubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest uncluster-ca"
	srv := server.New(server.Config{Store: st, CAPubkey: testCAPubkey})
	ts := httpTestServer(t, srv.Handler())

	jt := mintJoinToken(t, st)

	body, _ := json.Marshal(api.AgentRegisterRequest{
		JoinToken: jt, Name: "mac", Metadata: map[string]any{"os": "darwin"},
	})
	resp, err := http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("register: %v status=%d", err, resp.StatusCode)
	}
	var reg api.AgentRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()

	if reg.AgentID == "" {
		t.Errorf("agent_id empty")
	}
	if reg.AgentToken == "" {
		t.Errorf("agent_token empty")
	}
	if reg.CAPubkey != testCAPubkey {
		t.Errorf("ca_pubkey mismatch: got %q want %q", reg.CAPubkey, testCAPubkey)
	}
	// darwin → POSIX paths
	if reg.ExpectedPaths.CAPubkey != "/etc/ssh/uncluster_ca.pub" {
		t.Errorf("expected_paths.ca_pubkey: %q", reg.ExpectedPaths.CAPubkey)
	}
	if reg.ExpectedPaths.PrincipalsDir != "/etc/ssh/auth_principals" {
		t.Errorf("expected_paths.principals_dir: %q", reg.ExpectedPaths.PrincipalsDir)
	}

	// Using the join token twice must fail.
	resp, _ = http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 401 {
		t.Fatalf("reuse join token: status=%d", resp.StatusCode)
	}
}

// TestAgentRegister_WindowsPaths verifies Windows-specific expected_paths.
func TestAgentRegister_WindowsPaths(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "w.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	jt := mintJoinToken(t, st)
	body, _ := json.Marshal(api.AgentRegisterRequest{
		JoinToken: jt, Name: "win-box", Metadata: map[string]any{"os": "windows"},
	})
	resp, err := http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("register: %v status=%d", err, resp.StatusCode)
	}
	var reg api.AgentRegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()

	want := `C:\ProgramData\ssh\auth_principals`
	if reg.ExpectedPaths.PrincipalsDir != want {
		t.Errorf("windows principals_dir: got %q want %q", reg.ExpectedPaths.PrincipalsDir, want)
	}
}

// TestAgentRegister_AlreadyEnrolled verifies idempotency-by-rejection:
// re-registering with the same name returns 409.
func TestAgentRegister_AlreadyEnrolled(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "ae.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	jt1 := mintJoinToken(t, st)
	jt2 := mintJoinToken(t, st)

	body1, _ := json.Marshal(api.AgentRegisterRequest{JoinToken: jt1, Name: "dup"})
	resp, _ := http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body1))
	if resp.StatusCode != 200 {
		t.Fatalf("first register: status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// Second registration with different join token but same name → 409.
	body2, _ := json.Marshal(api.AgentRegisterRequest{JoinToken: jt2, Name: "dup"})
	resp, _ = http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body2))
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate name: status=%d, want 409", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestAgentRegister_CAPubkeyMatchesServer is the integration test from the
// acceptance criteria: register an agent, verify response carries CA pubkey
// matching the server's CA.
func TestAgentRegister_CAPubkeyMatchesServer(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "ca.db"))
	defer st.Close()

	const caLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIintegration uncluster-ca"
	srv := server.New(server.Config{Store: st, CAPubkey: caLine})
	ts := httpTestServer(t, srv.Handler())

	jt := mintJoinToken(t, st)
	body, _ := json.Marshal(api.AgentRegisterRequest{JoinToken: jt, Name: "int-node"})
	resp, err := http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("register: %v status=%d", err, resp.StatusCode)
	}
	var reg api.AgentRegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()

	if reg.CAPubkey != caLine {
		t.Errorf("ca_pubkey mismatch: got %q want %q", reg.CAPubkey, caLine)
	}
}

// --- V2 heartbeat tests ---

// mintAgentAndToken registers a V2 agent via the register endpoint and returns
// the agent_id and plaintext agent token.
func mintAgentAndToken(t *testing.T, st store.Store, ts *httptest.Server, name string) (agentID, agentTok string) {
	t.Helper()
	jt := mintJoinToken(t, st)
	body, _ := json.Marshal(api.AgentRegisterRequest{JoinToken: jt, Name: name})
	resp, err := http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("register: %v status=%d", err, resp.StatusCode)
	}
	var reg api.AgentRegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()
	return reg.AgentID, reg.AgentToken
}

// TestV2Heartbeat_RoundTrip verifies that a V2 heartbeat request returns ack_ts
// and server_time, and updates agents.last_seen_at in the store.
func TestV2Heartbeat_RoundTrip(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "hb.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	agentID, agentTok := mintAgentAndToken(t, st, ts, "hb-agent")

	observedAt := int64(1735689600)
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v2.0.0",
		ObservedAt:   observedAt,
		Endpoints: []api.AgentEndpoint{
			{Subnet: "home-lan", Address: "192.168.1.42"},
		},
		PolicyState: api.AgentPolicyState{
			AppliedVersion:  0,
			AppliedHash:     "",
			LastApplyStatus: "ok",
			LastApplyAt:     observedAt - 60,
		},
		Health: []api.AgentHealthCheck{
			{Component: "sshd", Check: "running", State: "ok"},
		},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("heartbeat POST: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("heartbeat status=%d", resp.StatusCode)
	}
	var hbResp api.V2HeartbeatResponse
	_ = json.NewDecoder(resp.Body).Decode(&hbResp)
	resp.Body.Close()

	if hbResp.AckTS != observedAt {
		t.Errorf("ack_ts = %d, want %d", hbResp.AckTS, observedAt)
	}
	if hbResp.ServerTime == 0 {
		t.Error("server_time should be non-zero")
	}
	if hbResp.Policy != nil {
		t.Errorf("policy should be null (S3b not yet implemented): %v", hbResp.Policy)
	}

	// Verify last_seen_at updated in store.
	ag, err := st.GetAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if ag.LastSeenAt == nil {
		t.Error("last_seen_at not updated after heartbeat")
	}
}

// TestV2Heartbeat_PolicyStatePersisted verifies that the server stores the
// agent's reported policy state.
func TestV2Heartbeat_PolicyStatePersisted(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "ps.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	agentID, agentTok := mintAgentAndToken(t, st, ts, "ps-agent")

	errMsg := "apply failed: bad principal"
	desiredV := int64(5)
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:      agentID,
		AgentVersion: "v2.0.0",
		ObservedAt:   1735689600,
		PolicyState: api.AgentPolicyState{
			DesiredVersion:  &desiredV,
			AppliedVersion:  4,
			AppliedHash:     "blake3:deadbeef",
			LastApplyStatus: "failed",
			LastApplyError:  &errMsg,
			LastApplyAt:     1735689500,
		},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("heartbeat status=%d", resp.StatusCode)
	}

	ps, err := st.GetAgentPolicyState(context.Background(), agentID)
	if err != nil {
		t.Fatalf("GetAgentPolicyState: %v", err)
	}
	if ps.AppliedVersion != 4 {
		t.Errorf("AppliedVersion = %d, want 4", ps.AppliedVersion)
	}
	if ps.LastApplyStatus != "failed" {
		t.Errorf("LastApplyStatus = %q, want failed", ps.LastApplyStatus)
	}
	if ps.LastApplyError == nil || *ps.LastApplyError != errMsg {
		t.Errorf("LastApplyError = %v, want %q", ps.LastApplyError, errMsg)
	}
}
