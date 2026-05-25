package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

// ---------------------------------------------------------------------------
// TestEndToEnd_V2Heartbeat — agent registers, heartbeats, server acks.
// ---------------------------------------------------------------------------

func TestEndToEnd_V2Heartbeat(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	// Seed a join token.
	joinTok, _ := token.Generate(token.KindJoin)
	joinHash, _ := token.HashSecret(joinTok.Secret)
	if _, err := st.CreateToken(context.Background(), store.NewTokenParams{
		ID: joinTok.ID, Kind: store.TokenJoin, SecretHash: joinHash, Label: "e2e-join",
	}); err != nil {
		t.Fatal(err)
	}

	// Register the agent via HTTP.
	regBody, _ := json.Marshal(api.AgentRegisterRequest{
		JoinToken: joinTok.String(),
		Name:      "e2e-agent",
		Metadata:  map[string]any{"os": "linux"},
	})
	regReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/register", bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := http.DefaultClient.Do(regReq)
	if err != nil || regResp.StatusCode != 200 {
		t.Fatalf("register: %v status=%d", err, regResp.StatusCode)
	}
	var regOut api.AgentRegisterResponse
	_ = json.NewDecoder(regResp.Body).Decode(&regOut)
	regResp.Body.Close()
	if regOut.AgentID == "" || regOut.AgentToken == "" {
		t.Fatalf("empty register response: %+v", regOut)
	}

	// Spin up agent in goroutine; it will heartbeat immediately.
	agentCtx, agentCancel := context.WithCancel(context.Background())
	t.Cleanup(agentCancel)

	ag := agent.New(agent.Config{
		Server:     ts.URL,
		AgentID:    regOut.AgentID,
		AgentName:  "e2e-agent",
		AgentToken: regOut.AgentToken,
	}, nil)
	go func() { _ = ag.Run(agentCtx) }()

	// Wait up to 5s for the agent's first heartbeat to be recorded.
	deadline := time.Now().Add(5 * time.Second)
	var lastSeen *time.Time
	for time.Now().Before(deadline) {
		rec, err := st.GetAgent(context.Background(), regOut.AgentID)
		if err == nil && rec.LastSeenAt != nil {
			lastSeen = rec.LastSeenAt
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastSeen == nil {
		t.Fatal("agent never sent a heartbeat within 5s")
	}
}

// ---------------------------------------------------------------------------
// TestEndToEnd_V2Revocation — agent registers, operator revokes, agent gets 410.
// ---------------------------------------------------------------------------

func TestEndToEnd_V2Revocation(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "rev.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	// Seed caller token for operator calls.
	callerTok, _ := token.Generate(token.KindCaller)
	callerHash, _ := token.HashSecret(callerTok.Secret)
	if _, err := st.CreateToken(context.Background(), store.NewTokenParams{
		ID: callerTok.ID, Kind: store.TokenCaller, SecretHash: callerHash, Label: "op",
	}); err != nil {
		t.Fatal(err)
	}

	// Seed a join token and register an agent.
	joinTok, _ := token.Generate(token.KindJoin)
	joinHash, _ := token.HashSecret(joinTok.Secret)
	_, _ = st.CreateToken(context.Background(), store.NewTokenParams{
		ID: joinTok.ID, Kind: store.TokenJoin, SecretHash: joinHash, Label: "j",
	})

	regBody, _ := json.Marshal(api.AgentRegisterRequest{
		JoinToken: joinTok.String(), Name: "rev-agent",
	})
	regReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/register", bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regResp, _ := http.DefaultClient.Do(regReq)
	var regOut api.AgentRegisterResponse
	_ = json.NewDecoder(regResp.Body).Decode(&regOut)
	regResp.Body.Close()
	if regOut.AgentID == "" {
		t.Fatal("empty register response")
	}

	// Confirm heartbeat works before revocation.
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID: regOut.AgentID, AgentVersion: "test", ObservedAt: time.Now().Unix(),
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+regOut.AgentToken)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, _ := http.DefaultClient.Do(hbReq)
	if hbResp.StatusCode != 200 {
		t.Fatalf("pre-revocation heartbeat: status=%d", hbResp.StatusCode)
	}
	hbResp.Body.Close()

	// Revoke the agent via the operator endpoint.
	delReq, _ := http.NewRequest("DELETE", ts.URL+"/v1/agents/"+regOut.AgentID, nil)
	delReq.Header.Set("Authorization", "Bearer "+callerTok.String())
	delResp, _ := http.DefaultClient.Do(delReq)
	if delResp.StatusCode != 204 {
		t.Fatalf("DELETE /v1/agents: status=%d", delResp.StatusCode)
	}
	delResp.Body.Close()

	// After revocation, heartbeat must return 410 Gone.
	hbBody2, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID: regOut.AgentID, AgentVersion: "test", ObservedAt: time.Now().Unix(),
	})
	hbReq2, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody2))
	hbReq2.Header.Set("Authorization", "Bearer "+regOut.AgentToken)
	hbReq2.Header.Set("Content-Type", "application/json")
	hbResp2, _ := http.DefaultClient.Do(hbReq2)
	if hbResp2.StatusCode != http.StatusGone {
		t.Fatalf("post-revocation heartbeat: want 410 Got %d", hbResp2.StatusCode)
	}
	hbResp2.Body.Close()
}

// ---------------------------------------------------------------------------
// TestEndToEnd_V2CertFlow — register → create ACL → heartbeat delivers policy.
// ---------------------------------------------------------------------------

func TestEndToEnd_V2CertFlow(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "cert.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	// Seed caller/operator token.
	callerTok, _ := token.Generate(token.KindCaller)
	callerHash, _ := token.HashSecret(callerTok.Secret)
	_, _ = st.CreateToken(context.Background(), store.NewTokenParams{
		ID: callerTok.ID, Kind: store.TokenCaller, SecretHash: callerHash, Label: "op",
	})

	// Register agent.
	joinTok, _ := token.Generate(token.KindJoin)
	joinHash, _ := token.HashSecret(joinTok.Secret)
	_, _ = st.CreateToken(context.Background(), store.NewTokenParams{
		ID: joinTok.ID, Kind: store.TokenJoin, SecretHash: joinHash, Label: "j",
	})
	regBody, _ := json.Marshal(api.AgentRegisterRequest{
		JoinToken: joinTok.String(), Name: "cert-agent",
	})
	regReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/register", bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regResp, _ := http.DefaultClient.Do(regReq)
	var regOut api.AgentRegisterResponse
	_ = json.NewDecoder(regResp.Body).Decode(&regOut)
	regResp.Body.Close()
	if regOut.AgentID == "" {
		t.Fatal("empty register response")
	}

	// Create an ACL entry granting the caller token SSH access as "alice".
	aclBody, _ := json.Marshal(api.CreateACLRequest{
		Caller:   callerTok.ID,
		Agent:    regOut.AgentID,
		Username: "alice",
	})
	aclReq, _ := http.NewRequest("POST", ts.URL+"/v1/acl", bytes.NewReader(aclBody))
	aclReq.Header.Set("Authorization", "Bearer "+callerTok.String())
	aclReq.Header.Set("Content-Type", "application/json")
	aclResp, _ := http.DefaultClient.Do(aclReq)
	if aclResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/acl: status=%d", aclResp.StatusCode)
	}
	aclResp.Body.Close()

	// Heartbeat: agent sends its current applied_hash="" so server should
	// respond with the full policy snapshot (v1, one principal: alice).
	hbBody, _ := json.Marshal(api.V2HeartbeatRequest{
		AgentID:     regOut.AgentID,
		AgentVersion: "test",
		ObservedAt:  time.Now().Unix(),
		PolicyState: api.AgentPolicyState{AppliedHash: ""},
	})
	hbReq, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+regOut.AgentToken)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, _ := http.DefaultClient.Do(hbReq)
	if hbResp.StatusCode != 200 {
		t.Fatalf("heartbeat: status=%d", hbResp.StatusCode)
	}
	var hbOut api.V2HeartbeatResponse
	_ = json.NewDecoder(hbResp.Body).Decode(&hbOut)
	hbResp.Body.Close()

	if hbOut.Policy == nil {
		t.Fatal("heartbeat response missing policy snapshot")
	}
	if len(hbOut.Policy.Principals) != 1 {
		t.Fatalf("want 1 principal, got %d", len(hbOut.Policy.Principals))
	}
	if hbOut.Policy.Principals[0].Username != "alice" {
		t.Fatalf("want principal alice, got %q", hbOut.Policy.Principals[0].Username)
	}
}
