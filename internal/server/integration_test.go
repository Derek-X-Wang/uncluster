package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

// mintV1NodeAndToken creates a V1 (node-based) agent pair directly in the
// store. Used by e2e tests that exercise the V1 task-execution path (heartbeat
// + poll + complete) which still operates on the nodes table until S11.
func mintV1NodeAndToken(t *testing.T, st store.Store, name string) (nodeID, agentTokenStr string) {
	t.Helper()
	n, err := st.CreateNode(context.Background(), store.NewNodeParams{Name: name})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	agentTok, _ := token.Generate(token.KindAgent)
	hash, _ := token.HashSecret(agentTok.Secret)
	nid := n.ID
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		agentTok.ID, store.TokenAgent, &nid, hash, "v1-agent:"+name); err != nil {
		t.Fatalf("InsertTokenWithID: %v", err)
	}
	return n.ID, agentTok.String()
}

// TestEndToEnd_RunCommand is a full integration test:
//   - real SQLite store in a tmpdir
//   - real HTTP server via httptest
//   - real agent running in a goroutine
//
// Flow: setup V1 node+token → heartbeat → POST task → poll until succeeded →
// GET /v1/tasks/{id}/chunks → assert output contains "hello" and "world".
// Note: Uses V1 node+token path directly (no register endpoint) because the
// V1 heartbeat / task handlers still operate on the nodes table.
func TestEndToEnd_RunCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("V1 task execution (bash + process groups) not supported on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
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
	// 2. Mint tokens via TestInsertHook / store helpers
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

	// V1 node + agent token (bypasses register endpoint; V1 task path).
	nodeID, agentTokenStr := mintV1NodeAndToken(t, st, "e2e-node")

	// ------------------------------------------------------------------
	// 3. Spin up the agent in a goroutine
	// ------------------------------------------------------------------
	agentCtx, agentCancel := context.WithCancel(context.Background())
	t.Cleanup(agentCancel)

	ag := agent.New(agent.Config{
		Server:     ts.URL,
		AgentID:    nodeID, // V1 compat: nodeID used as AgentID in config
		AgentName:  "e2e-node",
		AgentToken: agentTokenStr,
	}, nil)

	agentDone := make(chan error, 1)
	go func() { agentDone <- ag.Run(agentCtx) }()

	// Give the agent time to send the initial heartbeat and enter its poll loop.
	time.Sleep(500 * time.Millisecond)

	// ------------------------------------------------------------------
	// 5. POST a task via the CLI endpoint
	// ------------------------------------------------------------------
	taskBody, _ := json.Marshal(api.CreateTaskRequest{
		Node:    nodeID,
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

// ---------------------------------------------------------------------------
// Shared e2e harness for Task 14.2 acceptance tests
// ---------------------------------------------------------------------------

type e2eHarness struct {
	st        store.Store
	srv       *server.Server
	ts        *httptest.Server
	cliToken  string
	agentCtx  context.Context
	agentStop context.CancelFunc
	nodeName  string
	nodeID    string
}

func newHarness(t *testing.T, outputCap int64) *e2eHarness {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st, OutputCapBytes: outputCap})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	cliTok, _ := token.Generate(token.KindCLI)
	cliHash, _ := token.HashSecret(cliTok.Secret)
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		cliTok.ID, store.TokenCLI, nil, cliHash, "h")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	// V1 node+token path: V1 heartbeat/task handlers use nodes table until S11.
	nodeID, agentTokenStr := mintV1NodeAndToken(t, st, "h-node")

	a := agent.New(agent.Config{
		Server: ts.URL, AgentID: nodeID, AgentName: "h-node", AgentToken: agentTokenStr,
	}, nil)
	agentCtx, agentStop := context.WithCancel(ctx)
	go func() { _ = a.Run(agentCtx) }()
	t.Cleanup(agentStop)

	// Wait for first heartbeat so node.last_seen_at is set.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := st.GetNode(ctx, nodeID)
		if err == nil && n.LastSeenAt != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	return &e2eHarness{
		st: st, srv: srv, ts: ts,
		cliToken:  cliTok.String(),
		agentCtx:  agentCtx, agentStop: agentStop,
		nodeName:  "h-node", nodeID: nodeID,
	}
}

func (h *e2eHarness) createTask(t *testing.T, command string) string {
	t.Helper()
	body, _ := json.Marshal(api.CreateTaskRequest{Node: h.nodeName, Command: command})
	req, _ := http.NewRequest("POST", h.ts.URL+"/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.cliToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("create task: %v status=%d", err, resp.StatusCode)
	}
	var out api.CreateTaskResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return out.TaskID
}

func (h *e2eHarness) getTask(t *testing.T, id string) api.TaskDetail {
	t.Helper()
	req, _ := http.NewRequest("GET", h.ts.URL+"/v1/tasks/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+h.cliToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out api.TaskDetail
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return out
}

func (h *e2eHarness) cancelTask(t *testing.T, id string) {
	t.Helper()
	req, _ := http.NewRequest("POST", h.ts.URL+"/v1/tasks/"+id+"/cancel", nil)
	req.Header.Set("Authorization", "Bearer "+h.cliToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode >= 400 {
		t.Fatalf("cancel: %v status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()
}

func (h *e2eHarness) waitStatus(t *testing.T, id, want string, within time.Duration) api.TaskDetail {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		d := h.getTask(t, id)
		if d.Status == want {
			return d
		}
		time.Sleep(100 * time.Millisecond)
	}
	final := h.getTask(t, id)
	t.Fatalf("task %s status=%s, want %s (within %s)", id, final.Status, want, within)
	return final
}

// ---------------------------------------------------------------------------
// TestAcceptance_NoDoubleClaim — §11 #8
// ---------------------------------------------------------------------------

func TestAcceptance_NoDoubleClaim(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Register node directly (no agent running — we want to control polls).
	n, _ := st.CreateNode(context.Background(), store.NewNodeParams{Name: "c"})
	agentTok, _ := token.Generate(token.KindAgent)
	hash, _ := token.HashSecret(agentTok.Secret)
	nid := n.ID
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		agentTok.ID, store.TokenAgent, &nid, hash, "c")

	// Create exactly one pending task.
	_, _ = st.CreateTask(context.Background(), n.ID, "echo only-one", "", time.Now())

	poll := func() int {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/v1/agent/next-task", nil)
		req.Header.Set("Authorization", "Bearer "+agentTok.String())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return -1
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	ch := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() { ch <- poll() }()
	}
	got200, got204 := 0, 0
	for i := 0; i < 2; i++ {
		switch <-ch {
		case 200:
			got200++
		case 204:
			got204++
		}
	}
	if got200 != 1 || got204 != 1 {
		t.Fatalf("expected exactly one claim: 200=%d, 204=%d", got200, got204)
	}
}

// ---------------------------------------------------------------------------
// TestAcceptance_SilentCommandCancel — §11 #9
// ---------------------------------------------------------------------------

func TestAcceptance_SilentCommandCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("V1 task execution (bash + process groups) not supported on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	h := newHarness(t, 0) // default cap

	// sleep 60 produces no stdout/stderr — forces cancel delivery through heartbeat.
	id := h.createTask(t, "sleep 60")

	// Wait for the task to start (status=running) before cancelling.
	h.waitStatus(t, id, "running", 10*time.Second)

	start := time.Now()
	h.cancelTask(t, id)
	final := h.waitStatus(t, id, "cancelled", 20*time.Second)

	latency := time.Since(start)
	if latency > 15*time.Second {
		t.Fatalf("cancel latency %s exceeds 15s budget (spec acceptance §11 #9)", latency)
	}
	if final.FinishedAt == nil {
		t.Fatal("finished_at should be set on cancelled task")
	}
}

// ---------------------------------------------------------------------------
// TestAcceptance_OutputCap — §11 #10
// ---------------------------------------------------------------------------

func TestAcceptance_OutputCap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("V1 task execution (bash + process groups) not supported on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	const cap = int64(1024) // 1 KiB — small for fast test
	h := newHarness(t, cap)

	// Emit ~8 KiB so we're well above the cap.
	id := h.createTask(t, `yes | head -c 8192`)

	final := h.waitStatus(t, id, "succeeded", 15*time.Second)
	if !final.OutputTruncated {
		t.Fatalf("expected output_truncated=true; got task: %+v", final)
	}
	// output_bytes = actual trimmed bytes + truncation marker; allow a generous
	// envelope for the marker (the marker is ~45 bytes).
	if final.OutputBytes > cap+256 {
		t.Fatalf("output_bytes %d exceeds cap(%d)+256 marker envelope", final.OutputBytes, cap)
	}
	// The marker must appear in stored output.
	chunks, _ := h.st.ListChunks(context.Background(), id, "stdout", 0, 10000)
	var joined []byte
	for _, c := range chunks {
		joined = append(joined, c.Data...)
	}
	if !bytes.Contains(joined, []byte("output truncated")) {
		t.Fatalf("truncation marker missing from stored stdout")
	}
}
