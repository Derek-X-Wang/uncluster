package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestRunTokenCreate confirms create routes kind+label through the client and
// prints the plaintext (shown once) plus the id.
func TestRunTokenCreate(t *testing.T) {
	f := newFakeControlPlaneClient()
	var out bytes.Buffer
	if err := runTokenCreate(context.Background(), f, &out, "join", "windows-rig"); err != nil {
		t.Fatalf("runTokenCreate: %v", err)
	}
	if len(f.createdTokens) != 1 || f.createdTokens[0].Kind != "join" || f.createdTokens[0].Label != "windows-rig" {
		t.Fatalf("createdTokens = %+v, want one join/windows-rig", f.createdTokens)
	}
	s := out.String()
	if !strings.Contains(s, "token: uct_join_") || !strings.Contains(s, "id:") {
		t.Errorf("output = %q, want token + id lines", s)
	}
}

// TestRunTokenList renders active/used/revoked state.
func TestRunTokenList(t *testing.T) {
	revoked := int64(5)
	used := int64(3)
	f := newFakeControlPlaneClient()
	f.tokens = []api.TokenSummary{
		{ID: "tok_a", Kind: "caller", Label: "mbp"},
		{ID: "tok_b", Kind: "join", Label: "rig", RevokedAt: &revoked},
		{ID: "tok_c", Kind: "cli", Label: "ops", UsedAt: &used},
	}
	var out bytes.Buffer
	if err := runTokenList(context.Background(), f, &out); err != nil {
		t.Fatalf("runTokenList: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "tok_a") || !strings.Contains(s, "active") {
		t.Errorf("expected active row:\n%s", s)
	}
	if !strings.Contains(s, "revoked") {
		t.Errorf("expected revoked state:\n%s", s)
	}
	if !strings.Contains(s, "used") {
		t.Errorf("expected used state:\n%s", s)
	}
}

// TestRunTokenRevoke routes the id through the client.
func TestRunTokenRevoke(t *testing.T) {
	f := newFakeControlPlaneClient()
	if err := runTokenRevoke(context.Background(), f, "tok_x"); err != nil {
		t.Fatalf("runTokenRevoke: %v", err)
	}
	if len(f.revokedTokens) != 1 || f.revokedTokens[0] != "tok_x" {
		t.Fatalf("revokedTokens = %v, want [tok_x]", f.revokedTokens)
	}
}

// TestConfiguredClient_GuardsUnconfigured proves the config guard has exactly
// one implementation and one error message, shared by both the client-only and
// the config+client entry points. token ls/revoke previously skipped this guard.
func TestConfiguredClient_GuardsUnconfigured(t *testing.T) {
	// Isolate config resolution to an empty temp dir so no cli.toml exists.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, err := newConfiguredControlPlaneClient(); !errors.Is(err, errNotConfigured) {
		t.Errorf("newConfiguredControlPlaneClient err = %v, want errNotConfigured", err)
	}
	if _, _, err := loadConfiguredCLI(); !errors.Is(err, errNotConfigured) {
		t.Errorf("loadConfiguredCLI err = %v, want errNotConfigured", err)
	}
}
