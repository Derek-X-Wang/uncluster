package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestSelectACLEntry_MatchesByAgentIDAndUsername covers the core selection logic
// behind issue #141: when a Caller holds the same username on two Agents, the row
// must be selected by the *resolved* Agent ID, never by first-match across agents.
func TestSelectACLEntry_MatchesByAgentIDAndUsername(t *testing.T) {
	entries := []api.ACLEntrySummary{
		{ID: "acl_A", CallerTokenID: "caller_x", AgentID: "ag_A", Username: "derek"},
		{ID: "acl_B", CallerTokenID: "caller_x", AgentID: "ag_B", Username: "derek"},
	}

	got, err := selectACLEntry(entries, "ag_B", "derek")
	if err != nil {
		t.Fatalf("selectACLEntry(ag_B): unexpected error: %v", err)
	}
	if got.ID != "acl_B" {
		t.Errorf("selectACLEntry(ag_B) = %q, want acl_B", got.ID)
	}

	got, err = selectACLEntry(entries, "ag_A", "derek")
	if err != nil {
		t.Fatalf("selectACLEntry(ag_A): unexpected error: %v", err)
	}
	if got.ID != "acl_A" {
		t.Errorf("selectACLEntry(ag_A) = %q, want acl_A", got.ID)
	}

	if _, err := selectACLEntry(entries, "ag_C", "derek"); err == nil {
		t.Error("selectACLEntry(ag_C) should error when no row matches the agent")
	}
	if _, err := selectACLEntry(entries, "ag_A", "root"); err == nil {
		t.Error("selectACLEntry(ag_A, root) should error when username does not match")
	}
}

// TestRunACLGrant_ThroughFake exercises the grant command logic against the
// in-memory client and checks the rendered output.
func TestRunACLGrant_ThroughFake(t *testing.T) {
	f := newFakeControlPlaneClient()
	f.registerAgent("box-a", "ag_A")

	var out bytes.Buffer
	if err := runACLGrant(context.Background(), f, &out, "caller_x", "box-a", "derek"); err != nil {
		t.Fatalf("runACLGrant: %v", err)
	}
	if s := out.String(); !strings.Contains(s, "granted:") || !strings.Contains(s, "agent=ag_A") || !strings.Contains(s, "username=derek") {
		t.Errorf("grant output = %q, want granted line with agent=ag_A username=derek", s)
	}
	rows, _ := f.ListACL(context.Background(), "caller_x", "")
	if len(rows) != 1 {
		t.Fatalf("after grant, rows = %d, want 1", len(rows))
	}
}

// TestRunACLRevoke_ByName_DeletesCorrectRow is the #141 regression carried
// forward onto the seam: with two Agents granting the same Caller the same
// username, revoking by the second Agent's name must delete that Agent's row.
func TestRunACLRevoke_ByName_DeletesCorrectRow(t *testing.T) {
	f := newFakeControlPlaneClient()
	f.registerAgent("box-a", "ag_A")
	f.registerAgent("box-b", "ag_B")
	if _, err := f.GrantACL(context.Background(), "caller_x", "box-a", "derek"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.GrantACL(context.Background(), "caller_x", "box-b", "derek"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runACLRevoke(context.Background(), f, &out, "caller_x", "box-b", "derek"); err != nil {
		t.Fatalf("runACLRevoke by name: %v", err)
	}

	remaining, _ := f.ListACL(context.Background(), "caller_x", "")
	if len(remaining) != 1 || remaining[0].AgentID != "ag_A" {
		t.Fatalf("after revoking box-b, remaining = %+v, want only ag_A's row", remaining)
	}
}

// TestRunACLRevoke_UnresolvableName_Errors confirms an unresolvable name errors
// through the command and deletes nothing.
func TestRunACLRevoke_UnresolvableName_Errors(t *testing.T) {
	f := newFakeControlPlaneClient()
	f.registerAgent("box-a", "ag_A")
	if _, err := f.GrantACL(context.Background(), "caller_x", "box-a", "derek"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runACLRevoke(context.Background(), f, &out, "caller_x", "ghost", "derek"); err == nil {
		t.Fatal("runACLRevoke of unresolvable agent should error")
	}
	if rows, _ := f.ListACL(context.Background(), "caller_x", ""); len(rows) != 1 {
		t.Fatalf("rows after failed revoke = %d, want 1 (nothing deleted)", len(rows))
	}
}

// TestRunACLList_ThroughFake exercises the list command's plain and JSON output.
func TestRunACLList_ThroughFake(t *testing.T) {
	f := newFakeControlPlaneClient()
	f.registerAgent("box-a", "ag_A")
	if _, err := f.GrantACL(context.Background(), "caller_x", "box-a", "derek"); err != nil {
		t.Fatal(err)
	}

	var plain bytes.Buffer
	if err := runACLList(context.Background(), f, &plain, "", "", false); err != nil {
		t.Fatalf("runACLList: %v", err)
	}
	if s := plain.String(); !strings.Contains(s, "CALLER") || !strings.Contains(s, "caller_x") {
		t.Errorf("list output = %q, want header + caller_x row", s)
	}

	var asJSON bytes.Buffer
	if err := runACLList(context.Background(), f, &asJSON, "", "", true); err != nil {
		t.Fatalf("runACLList --json: %v", err)
	}
	if s := asJSON.String(); !strings.Contains(s, `"caller_token_id": "caller_x"`) {
		t.Errorf("list --json output = %q, want caller_token_id field", s)
	}
}
