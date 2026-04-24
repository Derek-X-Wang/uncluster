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
