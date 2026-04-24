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

func TestAgentRegisterAndHeartbeat(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
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
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	if reg.AgentToken == "" || reg.NodeID == "" {
		t.Fatalf("empty response: %+v", reg)
	}

	// Heartbeat with the returned agent token.
	hbody, _ := json.Marshal(api.HeartbeatRequest{Metadata: map[string]any{"load": 0.5}})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbody))
	req.Header.Set("Authorization", "Bearer "+reg.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("heartbeat: %v status=%d", err, resp.StatusCode)
	}

	// Using the join token twice must fail.
	resp, _ = http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 401 {
		t.Fatalf("reuse: status=%d", resp.StatusCode)
	}
}
