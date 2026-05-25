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

// ---- tokens ----

func TestCreateAndGetToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	tok, err := s.CreateToken(ctx, store.NewTokenParams{
		Kind:       store.TokenCaller,
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
	if got.Kind != store.TokenCaller || got.Label != "my-laptop" {
		t.Fatalf("unexpected token: %+v", got)
	}
}

func TestRevokeToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCaller, SecretHash: "h"})
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

// ---- V2 Agent ----

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
}

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

	byAgent, err := s.ListACL(ctx, store.ListACLFilter{AgentID: ag1.ID})
	if err != nil {
		t.Fatalf("ListACL by agent: %v", err)
	}
	if len(byAgent) != 2 {
		t.Errorf("want 2 entries for ag1, got %d", len(byAgent))
	}

	byCaller, err := s.ListACL(ctx, store.ListACLFilter{CallerTokenID: tok1.ID})
	if err != nil {
		t.Fatalf("ListACL by caller: %v", err)
	}
	if len(byCaller) != 2 {
		t.Errorf("want 2 entries for tok1, got %d", len(byCaller))
	}

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

// ---- S5: agent revocation ----

func TestRevokeAgent_SetsStatusAndRevokesToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "rev-agent"})
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{
		Kind:       store.TokenAgent,
		AgentID:    &ag.ID,
		SecretHash: "h",
		Label:      "agent:rev-agent",
	})

	if err := s.RevokeAgent(ctx, ag.ID, time.Now()); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}

	revoked, err := s.GetAgent(ctx, ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != store.AgentRevoked {
		t.Errorf("status = %s, want revoked", revoked.Status)
	}
	if revoked.Name == "rev-agent" {
		t.Errorf("name should have been renamed, got: %q", revoked.Name)
	}

	// Agent token should be revoked.
	gotTok, _ := s.GetTokenByID(ctx, tok.ID)
	if gotTok.RevokedAt == nil {
		t.Error("agent token should have revoked_at set")
	}
}

func TestRevokeAgent_NotFound(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	err := s.RevokeAgent(ctx, "ag_nonexistent", time.Now())
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestListAgents_ExcludesRevoked(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_, _ = s.CreateAgent(ctx, store.NewAgentParams{Name: "active-1"})
	ag2, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "active-2"})
	_ = s.RevokeAgent(ctx, ag2.ID, time.Now())

	list, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("want 1 active agent, got %d", len(list))
	}
	if list[0].Name != "active-1" {
		t.Errorf("unexpected agent name: %s", list[0].Name)
	}
}

func TestSetAgentFailClosedAfter(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ag, _ := s.CreateAgent(ctx, store.NewAgentParams{Name: "fca-agent"})

	secs := int64(3600)
	if err := s.SetAgentFailClosedAfter(ctx, ag.ID, &secs); err != nil {
		t.Fatalf("SetAgentFailClosedAfter: %v", err)
	}
	got, _ := s.GetAgent(ctx, ag.ID)
	if got.FailClosedAfter == nil || *got.FailClosedAfter != secs {
		t.Errorf("FailClosedAfter = %v, want %d", got.FailClosedAfter, secs)
	}

	// Clear it.
	if err := s.SetAgentFailClosedAfter(ctx, ag.ID, nil); err != nil {
		t.Fatalf("SetAgentFailClosedAfter (clear): %v", err)
	}
	got2, _ := s.GetAgent(ctx, ag.ID)
	if got2.FailClosedAfter != nil {
		t.Errorf("FailClosedAfter should be nil after clear, got %v", got2.FailClosedAfter)
	}
}

// ---- S6: cert audit log ----

func TestWriteAndListCertEvents(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)

	e := store.CertEvent{
		RequestID:     "req_abc123",
		TS:            now,
		CallerTokenID: "caller_tok_1",
		TargetAgentID: "ag_agent_1",
		Username:      "derek",
		CertPrincipal: "caller_tok_1",
		PubkeyFP:      "SHA256:abc",
		TTLSeconds:    300,
		Serial:        42,
		KeyID:         "uncluster:req_abc123:caller=caller_tok_1:agent=ag_agent_1:user=derek",
		Outcome:       "signed",
	}

	if err := s.WriteCertEvent(ctx, e); err != nil {
		t.Fatalf("WriteCertEvent: %v", err)
	}

	events, err := s.ListCertEvents(ctx, store.CertEventFilter{})
	if err != nil {
		t.Fatalf("ListCertEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	got := events[0]
	if got.RequestID != e.RequestID {
		t.Errorf("RequestID = %q, want %q", got.RequestID, e.RequestID)
	}
	if got.Outcome != "signed" {
		t.Errorf("Outcome = %q, want signed", got.Outcome)
	}
	if got.Serial != 42 {
		t.Errorf("Serial = %d, want 42", got.Serial)
	}
	if got.PubkeyFP != "SHA256:abc" {
		t.Errorf("PubkeyFP = %q", got.PubkeyFP)
	}
}

func TestListCertEvents_FilterByOutcome(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now()

	_ = s.WriteCertEvent(ctx, store.CertEvent{RequestID: "r1", TS: now, CallerTokenID: "c1", Outcome: "signed"})
	_ = s.WriteCertEvent(ctx, store.CertEvent{RequestID: "r2", TS: now, CallerTokenID: "c1", Outcome: "denied", DenialReason: "acl_miss"})
	_ = s.WriteCertEvent(ctx, store.CertEvent{RequestID: "r3", TS: now, CallerTokenID: "c2", Outcome: "signed"})

	signed, _ := s.ListCertEvents(ctx, store.CertEventFilter{Outcome: "signed"})
	if len(signed) != 2 {
		t.Errorf("signed: want 2, got %d", len(signed))
	}

	denied, _ := s.ListCertEvents(ctx, store.CertEventFilter{Outcome: "denied"})
	if len(denied) != 1 || denied[0].DenialReason != "acl_miss" {
		t.Errorf("denied: %+v", denied)
	}

	byCaller, _ := s.ListCertEvents(ctx, store.CertEventFilter{CallerTokenID: "c1"})
	if len(byCaller) != 2 {
		t.Errorf("by caller c1: want 2, got %d", len(byCaller))
	}
}

func TestWriteCertEvent_Idempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	e := store.CertEvent{RequestID: "dup_req", TS: time.Now(), CallerTokenID: "c", Outcome: "signed"}
	if err := s.WriteCertEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	// Second write with same request_id should be ignored (INSERT OR IGNORE).
	if err := s.WriteCertEvent(ctx, e); err != nil {
		t.Fatalf("second write should be idempotent: %v", err)
	}
	events, _ := s.ListCertEvents(ctx, store.CertEventFilter{})
	if len(events) != 1 {
		t.Errorf("want 1 row (idempotent), got %d", len(events))
	}
}

// ---- update policy (S8b) ----

func TestUpdatePolicy_GetBeforeSet_ReturnsNotFound(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, err := s.GetUpdatePolicy(ctx)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestUpdatePolicy_SetAndGet(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	err := s.SetUpdatePolicy(ctx, store.SetUpdatePolicyParams{
		ExpectedVersion:   "v2.1.0",
		AssetURLTemplate:  "https://example.com/{os}/{arch}/uncluster-{version}",
		SHA256URLTemplate: "https://example.com/{os}/{arch}/uncluster-{version}.sha256",
		Force:             true,
	})
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := s.GetUpdatePolicy(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ExpectedVersion != "v2.1.0" {
		t.Errorf("expected_version = %q, want v2.1.0", got.ExpectedVersion)
	}
	if !got.Force {
		t.Error("force should be true")
	}
}

func TestUpdatePolicy_Upsert(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_ = s.SetUpdatePolicy(ctx, store.SetUpdatePolicyParams{ExpectedVersion: "v1.0.0"})
	_ = s.SetUpdatePolicy(ctx, store.SetUpdatePolicyParams{ExpectedVersion: "v2.0.0", Force: false})

	got, err := s.GetUpdatePolicy(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ExpectedVersion != "v2.0.0" {
		t.Errorf("want v2.0.0 after upsert, got %q", got.ExpectedVersion)
	}
}
