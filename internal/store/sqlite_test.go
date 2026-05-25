package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/store"
)

func newStore(t *testing.T) store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateAndGetToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	tok, err := s.CreateToken(ctx, store.NewTokenParams{
		Kind:       store.TokenCLI,
		SecretHash: "$argon2id$...",
		Label:      "my-laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTokenByID(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != store.TokenCLI || got.Label != "my-laptop" {
		t.Fatalf("unexpected token: %+v", got)
	}
}

func TestRevokeToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCLI, SecretHash: "h"})
	if err := s.RevokeToken(ctx, tok.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTokenByID(ctx, tok.ID)
	if got.RevokedAt == nil {
		t.Fatal("expected RevokedAt to be set")
	}
}

func TestMarkJoinTokenUsed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenJoin, SecretHash: "h"})
	if err := s.MarkJoinTokenUsed(ctx, tok.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTokenByID(ctx, tok.ID)
	if got.UsedAt == nil {
		t.Fatal("expected UsedAt to be set")
	}
	// Using twice should fail.
	if err := s.MarkJoinTokenUsed(ctx, tok.ID, time.Now()); err == nil {
		t.Fatal("expected ErrTokenUsed on second use")
	}
}

func TestCreateAndListNodes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, err := s.CreateNode(ctx, store.NewNodeParams{Name: "old-macbook", Metadata: `{"os":"darwin"}`})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNodeByName(ctx, "old-macbook")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != n.ID || got.Status != store.NodeOnline {
		t.Fatalf("unexpected node: %+v", got)
	}
	list, _ := s.ListNodes(ctx)
	if len(list) != 1 {
		t.Fatalf("ListNodes len: got %d want 1", len(list))
	}
}

func TestCreateNodeRejectsDuplicateName(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.CreateNode(ctx, store.NewNodeParams{Name: "dup"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateNode(ctx, store.NewNodeParams{Name: "dup"})
	if err == nil || !errors.Is(err, store.ErrNameTaken) {
		t.Fatalf("expected ErrNameTaken, got: %v", err)
	}
}

func TestRevokeNodeRenamesAndFreesName(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "laptop"})
	// Create an agent token for this node.
	_, _ = s.CreateToken(ctx, store.NewTokenParams{
		Kind: store.TokenAgent, NodeID: &n.ID, SecretHash: "h",
	})
	if err := s.RevokeNode(ctx, n.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	revoked, _ := s.GetNode(ctx, n.ID)
	if revoked.Status != store.NodeRevoked {
		t.Fatal("status not revoked")
	}
	if revoked.Name == "laptop" {
		t.Fatalf("name should have been renamed, got: %q", revoked.Name)
	}
	// Same name must be available for a fresh node.
	if _, err := s.CreateNode(ctx, store.NewNodeParams{Name: "laptop"}); err != nil {
		t.Fatalf("name should be free: %v", err)
	}
}

func TestAtomicClaim_NoDoubleAssignment(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	task, _ := s.CreateTask(ctx, n.ID, "echo hi", "cli", time.Now())

	// Two concurrent claim attempts: exactly one wins.
	type result struct {
		task *store.Task
		err  error
	}
	ch := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			got, err := s.ClaimNextPending(ctx, n.ID, time.Now())
			ch <- result{got, err}
		}()
	}
	var winners int
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.task != nil {
			if r.task.ID != task.ID {
				t.Fatalf("claimed wrong task: %q", r.task.ID)
			}
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", winners)
	}
}

func TestClaimSkipsCancelled(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	task, _ := s.CreateTask(ctx, n.ID, "nope", "cli", time.Now())
	_ = s.MarkTaskCancelled(ctx, task.ID, time.Now())

	got, err := s.ClaimNextPending(ctx, n.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil (cancelled task not claimable), got: %+v", got)
	}
}

func TestCompleteTask(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	task, _ := s.CreateTask(ctx, n.ID, "echo hi", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())
	if err := s.CompleteTask(ctx, task.ID, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTask(ctx, task.ID)
	if got.Status != store.TaskSucceeded {
		t.Fatalf("status: got %s want succeeded", got.Status)
	}
	if got.ExitCode == nil || *got.ExitCode != 0 {
		t.Fatalf("exit_code: got %v want 0", got.ExitCode)
	}
}

func TestCompleteAfterCancellingBecomesCancelled(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	task, _ := s.CreateTask(ctx, n.ID, "sleep", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())
	_ = s.MarkTaskCancelling(ctx, task.ID)
	_ = s.CompleteTask(ctx, task.ID, -1, time.Now())

	got, _ := s.GetTask(ctx, task.ID)
	if got.Status != store.TaskCancelled {
		t.Fatalf("status: got %s want cancelled", got.Status)
	}
}

func TestFindStaleRunning(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	_, _ = s.CreateTask(ctx, n.ID, "stuck", "cli", time.Now().Add(-10*time.Minute))
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now().Add(-10*time.Minute))
	// No heartbeat has been recorded.
	got, err := s.FindStaleRunning(ctx, time.Now().Add(-60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 stale, got %d", len(got))
	}
}

func TestAppendChunk(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	tk, _ := s.CreateTask(ctx, n.ID, "echo hi", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())

	res, err := s.AppendChunk(ctx, tk.ID, "stdout", []byte("hello\n"), time.Now(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Fatal("unexpected truncation on small chunk")
	}

	chunks, err := s.ListChunks(ctx, tk.ID, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || string(chunks[0].Data) != "hello\n" {
		t.Fatalf("unexpected chunks: %+v", chunks)
	}
}

func TestAppendChunk_OutputCap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	tk, _ := s.CreateTask(ctx, n.ID, "yes", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())

	cap := int64(16)
	// First chunk of 10 bytes: fits under the 16-byte cap.
	r1, _ := s.AppendChunk(ctx, tk.ID, "stdout", []byte("0123456789"), time.Now(), cap)
	if r1.Truncated {
		t.Fatal("chunk 1 should not be truncated")
	}
	// Second chunk of 10 bytes: only 6 bytes fit; trimmed; truncation marker appended.
	r2, _ := s.AppendChunk(ctx, tk.ID, "stdout", []byte("abcdefghij"), time.Now(), cap)
	if !r2.Truncated {
		t.Fatal("chunk 2 should have been truncated")
	}

	got, _ := s.GetTask(ctx, tk.ID)
	if !got.OutputTruncated {
		t.Fatal("task.OutputTruncated must be set")
	}
	if got.OutputBytes > cap+256 {
		// 256 is a generous envelope for the truncation marker.
		t.Fatalf("output_bytes exceeds cap+marker: %d", got.OutputBytes)
	}

	// Subsequent writes should report truncated without inserting more.
	r3, _ := s.AppendChunk(ctx, tk.ID, "stdout", []byte("more"), time.Now(), cap)
	if !r3.Truncated {
		t.Fatal("chunk 3 should see truncated")
	}
}

// ---- V2 Agent store tests ----

func TestCreateAndGetAgent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ag, err := s.CreateAgent(ctx, store.NewAgentParams{Name: "linux-box"})
	if err != nil {
		t.Fatal(err)
	}
	if ag.ID == "" || ag.Name != "linux-box" {
		t.Fatalf("unexpected agent: %+v", ag)
	}
	if ag.Status != store.AgentOnline {
		t.Fatalf("status: got %s want online", ag.Status)
	}

	got, err := s.GetAgent(ctx, ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != ag.ID {
		t.Fatalf("GetAgent mismatch: %+v vs %+v", got, ag)
	}

	byName, err := s.GetAgentByName(ctx, "linux-box")
	if err != nil {
		t.Fatal(err)
	}
	if byName.ID != ag.ID {
		t.Fatalf("GetAgentByName mismatch: %+v", byName)
	}
}

func TestCreateAgentRejectsDuplicateName(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.CreateAgent(ctx, store.NewAgentParams{Name: "dup"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateAgent(ctx, store.NewAgentParams{Name: "dup"})
	if err == nil || !errors.Is(err, store.ErrAgentNameTaken) {
		t.Fatalf("expected ErrAgentNameTaken, got: %v", err)
	}
}

func TestCreateAgentTokenLinksAgentID(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "mac"})
	tok, err := s.CreateToken(ctx, store.NewTokenParams{
		Kind:       store.TokenAgent,
		AgentID:    &ag.ID,
		SecretHash: "h",
		Label:      "agent:mac",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTokenByID(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID == nil || *got.AgentID != ag.ID {
		t.Fatalf("AgentID mismatch: %v", got.AgentID)
	}
	if got.NodeID != nil {
		t.Fatalf("NodeID should be nil for V2 agent token, got: %v", got.NodeID)
	}
}

func TestListChunks_PerStream(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	tk, _ := s.CreateTask(ctx, n.ID, "echo", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())

	_, _ = s.AppendChunk(ctx, tk.ID, "stdout", []byte("OUT"), time.Now(), 1<<20)
	_, _ = s.AppendChunk(ctx, tk.ID, "stderr", []byte("ERR"), time.Now(), 1<<20)

	out, _ := s.ListChunks(ctx, tk.ID, "stdout", 0, 100)
	if len(out) != 1 || string(out[0].Data) != "OUT" {
		t.Fatalf("stdout: %+v", out)
	}
	errc, _ := s.ListChunks(ctx, tk.ID, "stderr", 0, 100)
	if len(errc) != 1 || string(errc[0].Data) != "ERR" {
		t.Fatalf("stderr: %+v", errc)
	}
}

// ---- V2 agent heartbeat + policy state ----

func TestUpdateAgentHeartbeat(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "hb-box"})

	now := time.Now().Truncate(time.Second)
	if err := s.UpdateAgentHeartbeat(ctx, ag.ID, "v2.0.1", now); err != nil {
		t.Fatalf("UpdateAgentHeartbeat: %v", err)
	}
	updated, err := s.GetAgent(ctx, ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.AgentVersion != "v2.0.1" {
		t.Errorf("AgentVersion = %q, want v2.0.1", updated.AgentVersion)
	}
	if updated.LastSeenAt == nil {
		t.Fatal("LastSeenAt should be set after heartbeat")
	}
	if !updated.LastSeenAt.Equal(now) {
		t.Errorf("LastSeenAt = %v, want %v", updated.LastSeenAt, now)
	}
}

func TestUpsertAndGetAgentPolicyState(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "ps-box"})

	// Initial upsert.
	lastApplyAt := time.Now().Truncate(time.Second).Add(-1 * time.Minute)
	if err := s.UpsertAgentPolicyState(ctx, store.UpsertAgentPolicyStateParams{
		AgentID:         ag.ID,
		DesiredVersion:  nil,
		AppliedVersion:  0,
		AppliedHash:     "",
		LastApplyStatus: "ok",
		LastApplyError:  nil,
		LastApplyAt:     lastApplyAt,
	}); err != nil {
		t.Fatalf("UpsertAgentPolicyState (initial): %v", err)
	}

	ps, err := s.GetAgentPolicyState(ctx, ag.ID)
	if err != nil {
		t.Fatalf("GetAgentPolicyState: %v", err)
	}
	if ps.AgentID != ag.ID {
		t.Errorf("AgentID mismatch: %s", ps.AgentID)
	}
	if ps.DesiredVersion != nil {
		t.Errorf("DesiredVersion should be nil initially")
	}
	if ps.LastApplyStatus != "ok" {
		t.Errorf("LastApplyStatus = %q, want ok", ps.LastApplyStatus)
	}

	// Second upsert — update values.
	desiredV := int64(3)
	errMsg := "policy parse error"
	if err := s.UpsertAgentPolicyState(ctx, store.UpsertAgentPolicyStateParams{
		AgentID:         ag.ID,
		DesiredVersion:  &desiredV,
		AppliedVersion:  2,
		AppliedHash:     "blake3:abc123",
		LastApplyStatus: "failed",
		LastApplyError:  &errMsg,
		LastApplyAt:     lastApplyAt,
	}); err != nil {
		t.Fatalf("UpsertAgentPolicyState (update): %v", err)
	}

	ps2, err := s.GetAgentPolicyState(ctx, ag.ID)
	if err != nil {
		t.Fatalf("GetAgentPolicyState after update: %v", err)
	}
	if ps2.DesiredVersion == nil || *ps2.DesiredVersion != 3 {
		t.Errorf("DesiredVersion = %v, want 3", ps2.DesiredVersion)
	}
	if ps2.AppliedVersion != 2 {
		t.Errorf("AppliedVersion = %d, want 2", ps2.AppliedVersion)
	}
	if ps2.AppliedHash != "blake3:abc123" {
		t.Errorf("AppliedHash = %q", ps2.AppliedHash)
	}
	if ps2.LastApplyStatus != "failed" {
		t.Errorf("LastApplyStatus = %q, want failed", ps2.LastApplyStatus)
	}
	if ps2.LastApplyError == nil || *ps2.LastApplyError != errMsg {
		t.Errorf("LastApplyError = %v, want %q", ps2.LastApplyError, errMsg)
	}
}

func TestGetAgentPolicyState_NotFound(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, err := s.GetAgentPolicyState(ctx, "ag_nonexistent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

// ---- V2 ACL + policy projection ----

func TestCreateAndGetACL(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "target-box"})
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h", Label: "caller"})

	e, err := s.CreateACL(ctx, store.CreateACLParams{
		CallerTokenID: tok.ID,
		AgentID:       ag.ID,
		Username:      "derek",
	})
	if err != nil {
		t.Fatalf("CreateACL: %v", err)
	}
	if e.ID == "" || e.CallerTokenID != tok.ID || e.AgentID != ag.ID || e.Username != "derek" {
		t.Errorf("unexpected entry: %+v", e)
	}

	got, err := s.GetACL(ctx, e.ID)
	if err != nil {
		t.Fatalf("GetACL: %v", err)
	}
	if got.ID != e.ID {
		t.Errorf("GetACL id mismatch: %s", got.ID)
	}
}

func TestCreateACL_Idempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "idem-box"})
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h"})

	e1, err := s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok.ID, AgentID: ag.ID, Username: "root"})
	if err != nil {
		t.Fatalf("first CreateACL: %v", err)
	}
	e2, err := s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok.ID, AgentID: ag.ID, Username: "root"})
	if err != nil {
		t.Fatalf("second (idempotent) CreateACL: %v", err)
	}
	if e1.ID != e2.ID {
		t.Errorf("idempotent re-grant returned different ids: %s vs %s", e1.ID, e2.ID)
	}
}

func TestDeleteACL(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "del-box"})
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h"})
	e, _ := s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok.ID, AgentID: ag.ID, Username: "alice"})

	if err := s.DeleteACL(ctx, e.ID); err != nil {
		t.Fatalf("DeleteACL: %v", err)
	}
	// Second delete should ErrNotFound.
	if err := s.DeleteACL(ctx, e.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second delete, got: %v", err)
	}
}

func TestListACL_Filters(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ag1, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "ls-box-1"})
	ag2, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "ls-box-2"})
	tok1, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h1"})
	tok2, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h2"})

	_, _ = s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok1.ID, AgentID: ag1.ID, Username: "derek"})
	_, _ = s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok2.ID, AgentID: ag1.ID, Username: "alice"})
	_, _ = s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok1.ID, AgentID: ag2.ID, Username: "derek"})

	// Filter by agent.
	byAgent, err := s.ListACL(ctx, store.ListACLFilter{AgentID: ag1.ID})
	if err != nil {
		t.Fatalf("ListACL by agent: %v", err)
	}
	if len(byAgent) != 2 {
		t.Errorf("want 2 entries for ag1, got %d", len(byAgent))
	}

	// Filter by caller.
	byCaller, err := s.ListACL(ctx, store.ListACLFilter{CallerTokenID: tok1.ID})
	if err != nil {
		t.Fatalf("ListACL by caller: %v", err)
	}
	if len(byCaller) != 2 {
		t.Errorf("want 2 entries for tok1, got %d", len(byCaller))
	}

	// All.
	all, err := s.ListACL(ctx, store.ListACLFilter{})
	if err != nil {
		t.Fatalf("ListACL all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("want 3 total entries, got %d", len(all))
	}
}

func TestGetPolicySnapshot_Empty(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "snap-empty"})
	snap, err := s.GetPolicySnapshot(ctx, ag.ID)
	if err != nil {
		t.Fatalf("GetPolicySnapshot: %v", err)
	}
	if snap.Version != 0 || snap.Hash != "" || len(snap.Principals) != 0 {
		t.Errorf("expected empty snapshot, got: %+v", snap)
	}
}

func TestGetPolicySnapshot_Version(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "snap-v"})
	tok1, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h1"})
	tok2, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h2"})

	// Grant 1.
	e1, err := s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok1.ID, AgentID: ag.ID, Username: "derek"})
	if err != nil {
		t.Fatalf("CreateACL: %v", err)
	}
	snap1, err := s.GetPolicySnapshot(ctx, ag.ID)
	if err != nil {
		t.Fatalf("GetPolicySnapshot after 1 grant: %v", err)
	}
	if snap1.Version != 1 {
		t.Errorf("expected version 1 after 1 grant, got %d", snap1.Version)
	}
	if snap1.Hash == "" {
		t.Error("hash should be non-empty after grant")
	}
	if len(snap1.Principals) != 1 || snap1.Principals[0].Username != "derek" {
		t.Errorf("unexpected principals: %+v", snap1.Principals)
	}

	// Grant 2 (different caller, same user).
	_, _ = s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok2.ID, AgentID: ag.ID, Username: "derek"})
	snap2, _ := s.GetPolicySnapshot(ctx, ag.ID)
	if snap2.Version != 2 {
		t.Errorf("expected version 2 after 2nd grant, got %d", snap2.Version)
	}
	if len(snap2.Principals[0].CallerTokenIDs) != 2 {
		t.Errorf("expected 2 caller_token_ids for derek, got %d", len(snap2.Principals[0].CallerTokenIDs))
	}

	// Revoke 1st grant.
	_ = s.DeleteACL(ctx, e1.ID)
	snap3, _ := s.GetPolicySnapshot(ctx, ag.ID)
	if snap3.Version != 3 {
		t.Errorf("expected version 3 after revoke, got %d", snap3.Version)
	}
	if snap3.Hash == snap1.Hash {
		t.Error("hash should change after revoke")
	}
}

func TestGetPolicySnapshot_Deterministic(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "snap-det"})
	tok1, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h1"})
	tok2, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h2"})

	_, _ = s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok1.ID, AgentID: ag.ID, Username: "alice"})
	_, _ = s.CreateACL(ctx, store.CreateACLParams{CallerTokenID: tok2.ID, AgentID: ag.ID, Username: "bob"})

	snap1, _ := s.GetPolicySnapshot(ctx, ag.ID)
	snap2, _ := s.GetPolicySnapshot(ctx, ag.ID)

	if snap1.Hash != snap2.Hash {
		t.Errorf("hash not deterministic: %s vs %s", snap1.Hash, snap2.Hash)
	}
}
