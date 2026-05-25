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
