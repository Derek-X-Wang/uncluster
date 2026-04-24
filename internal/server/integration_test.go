package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// TestEndToEnd_RunCommand is a full integration test:
//   - real SQLite store in a tmpdir
//   - real HTTP server via httptest
//   - real agent running in a goroutine
//
// Flow: register agent -> heartbeat -> POST task -> poll until succeeded ->
// GET /v1/tasks/{id}/chunks -> assert output contains "hello" and "world".
func TestEndToEnd_RunCommand(t *testing.T) {
	// ------------------------------------------------------------------
	// 1. Store + server + httptest
	// ------------------------------------------------------------------
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	// ------------------------------------------------------------------
	// 2. Mint tokens via TestInsertHook
	// ------------------------------------------------------------------
	// CLI token (used to create tasks).
	cliTok, _ := token.Generate(token.KindCLI)
	cliHash, _ := token.HashSecret(cliTok.Secret)
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(
		context.Background(), cliTok.ID, store.TokenCLI, nil, cliHash, "e2e-cli",
	); err != nil {
		t.Fatal(err)
	}
	cliBearerToken := cliTok.String()

	// Join token (used by the agent to register).
	joinTok, _ := token.Generate(token.KindJoin)
	joinHash, _ := token.HashSecret(joinTok.Secret)
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(
		context.Background(), joinTok.ID, store.TokenJoin, nil, joinHash, "e2e-join",
	); err != nil {
		t.Fatal(err)
	}
	joinBearerToken := joinTok.String()

	// ------------------------------------------------------------------
	// 3. Register the agent via HTTP (using agent.NewServerClient)
	// ------------------------------------------------------------------
	registrar := agent.NewServerClient(ts.URL, "")
	regResp, err := registrar.Register(context.Background(), api.AgentRegisterRequest{
		JoinToken: joinBearerToken,
		Name:      "e2e-node",
		Metadata:  map[string]any{"test": true},
	})
	if err != nil {
		t.Fatalf("agent register: %v", err)
	}
	if regResp.AgentToken == "" || regResp.NodeID == "" {
		t.Fatalf("empty register response: %+v", regResp)
	}

	// ------------------------------------------------------------------
	// 4. Spin up the agent in a goroutine
	// ------------------------------------------------------------------
	agentCtx, agentCancel := context.WithCancel(context.Background())
	t.Cleanup(agentCancel)

	ag := agent.New(agent.Config{
		Server:     ts.URL,
		NodeID:     regResp.NodeID,
		NodeName:   "e2e-node",
		AgentToken: regResp.AgentToken,
	}, nil)

	agentDone := make(chan error, 1)
	go func() { agentDone <- ag.Run(agentCtx) }()

	// Give the agent time to send the initial heartbeat and enter its poll loop.
	time.Sleep(500 * time.Millisecond)

	// ------------------------------------------------------------------
	// 5. POST a task via the CLI endpoint
	// ------------------------------------------------------------------
	taskBody, _ := json.Marshal(api.CreateTaskRequest{
		Node:    regResp.NodeID,
		Command: "echo hello && echo world",
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tasks", bytes.NewReader(taskBody))
	req.Header.Set("Authorization", "Bearer "+cliBearerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/tasks: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/tasks: status=%d", resp.StatusCode)
	}
	var createResp api.CreateTaskResponse
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	resp.Body.Close()
	taskID := createResp.TaskID
	if taskID == "" {
		t.Fatal("empty task_id in create response")
	}

	// ------------------------------------------------------------------
	// 6. Poll GET /v1/tasks/{id} until status == "succeeded" (10s deadline)
	// ------------------------------------------------------------------
	deadline := time.Now().Add(10 * time.Second)
	var finalTask api.TaskDetail
	for {
		if time.Now().After(deadline) {
			t.Fatalf("task %q did not succeed within 10s (last status: %q)", taskID, finalTask.Status)
		}
		pollReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/tasks/%s", ts.URL, taskID), nil)
		pollReq.Header.Set("Authorization", "Bearer "+cliBearerToken)
		pollResp, err := http.DefaultClient.Do(pollReq)
		if err != nil {
			t.Fatalf("poll GET /v1/tasks/%s: %v", taskID, err)
		}
		if err := json.NewDecoder(pollResp.Body).Decode(&finalTask); err != nil {
			pollResp.Body.Close()
			t.Fatalf("decode task detail: %v", err)
		}
		pollResp.Body.Close()

		if finalTask.Status == "succeeded" {
			break
		}
		if finalTask.Status == "failed" || finalTask.Status == "cancelled" {
			t.Fatalf("task ended with unexpected status %q", finalTask.Status)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// ------------------------------------------------------------------
	// 7. GET /v1/tasks/{id}/chunks, concatenate data, assert output
	// ------------------------------------------------------------------
	chunkReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/v1/tasks/%s/chunks", ts.URL, taskID), nil)
	chunkReq.Header.Set("Authorization", "Bearer "+cliBearerToken)
	chunkResp, err := http.DefaultClient.Do(chunkReq)
	if err != nil {
		t.Fatalf("GET /v1/tasks/%s/chunks: %v", taskID, err)
	}
	if chunkResp.StatusCode != http.StatusOK {
		t.Fatalf("chunks status=%d", chunkResp.StatusCode)
	}

	var chunksResponse api.ChunksResponse
	if err := json.NewDecoder(chunkResp.Body).Decode(&chunksResponse); err != nil {
		t.Fatalf("decode chunks response: %v", err)
	}
	chunkResp.Body.Close()

	// Concatenate all chunk data bytes.
	var combined []byte
	for _, c := range chunksResponse.Chunks {
		combined = append(combined, c.Data...)
	}
	output := string(combined)

	if !bytes.Contains(combined, []byte("hello")) {
		t.Errorf("output missing 'hello'; got: %q", output)
	}
	if !bytes.Contains(combined, []byte("world")) {
		t.Errorf("output missing 'world'; got: %q", output)
	}

	// ------------------------------------------------------------------
	// 8. Shut down the agent cleanly
	// ------------------------------------------------------------------
	agentCancel()
	select {
	case agentErr := <-agentDone:
		if agentErr != nil {
			t.Logf("agent exited with: %v", agentErr)
		}
	case <-time.After(3 * time.Second):
		t.Log("agent did not exit within 3s after cancel (non-fatal)")
	}
}
