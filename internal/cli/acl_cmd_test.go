package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	// Selecting for ag_B must return acl_B even though acl_A comes first and shares
	// the same caller + username.
	got, err := selectACLEntry(entries, "ag_B", "derek")
	if err != nil {
		t.Fatalf("selectACLEntry(ag_B): unexpected error: %v", err)
	}
	if got.ID != "acl_B" {
		t.Errorf("selectACLEntry(ag_B) = %q, want acl_B", got.ID)
	}

	// Selecting for ag_A must return acl_A.
	got, err = selectACLEntry(entries, "ag_A", "derek")
	if err != nil {
		t.Fatalf("selectACLEntry(ag_A): unexpected error: %v", err)
	}
	if got.ID != "acl_A" {
		t.Errorf("selectACLEntry(ag_A) = %q, want acl_A", got.ID)
	}

	// No entry for the resolved agent → error, never a silent match.
	if _, err := selectACLEntry(entries, "ag_C", "derek"); err == nil {
		t.Error("selectACLEntry(ag_C) should error when no row matches the agent")
	}

	// Username mismatch → error.
	if _, err := selectACLEntry(entries, "ag_A", "root"); err == nil {
		t.Error("selectACLEntry(ag_A, root) should error when username does not match")
	}
}

// aclRevokeTestServer builds an httptest server that resolves agent names, lists
// ACL rows, and records which ACL id was deleted. resolvable maps agent name/id →
// canonical agent id; an unresolvable arg yields 404.
type aclRevokeTestServer struct {
	*httptest.Server
	deletedIDs []string
}

func newACLRevokeTestServer(t *testing.T, resolvable map[string]string, entries []api.ACLEntrySummary) *aclRevokeTestServer {
	t.Helper()
	s := &aclRevokeTestServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/agents/"):
			name := strings.TrimPrefix(r.URL.Path, "/v1/agents/")
			id, ok := resolvable[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"agent not found"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(api.AgentDetail{ID: id, Name: name})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/acl":
			_ = json.NewEncoder(w).Encode(entries)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/acl/"):
			s.deletedIDs = append(s.deletedIDs, strings.TrimPrefix(r.URL.Path, "/v1/acl/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func runACLRevoke(t *testing.T, serverURL string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := SaveCLIConfig(CLIConfig{Server: serverURL, Token: "uct_caller_test_secret"}); err != nil {
		t.Fatalf("SaveCLIConfig: %v", err)
	}
	cmd := newACLRevokeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestACLRevoke_ByName_DeletesCorrectRow is the regression test for issue #141:
// with two Agents granting the same Caller the same username, revoking by the
// second Agent's name must delete that Agent's row, not the first match.
func TestACLRevoke_ByName_DeletesCorrectRow(t *testing.T) {
	entries := []api.ACLEntrySummary{
		{ID: "acl_A", CallerTokenID: "caller_x", AgentID: "ag_A", Username: "derek"},
		{ID: "acl_B", CallerTokenID: "caller_x", AgentID: "ag_B", Username: "derek"},
	}
	ts := newACLRevokeTestServer(t, map[string]string{"box-b": "ag_B", "box-a": "ag_A"}, entries)

	out, err := runACLRevoke(t, ts.URL, "caller_x", "box-b", "--as", "derek")
	if err != nil {
		t.Fatalf("revoke by name: unexpected error: %v (out=%q)", err, out)
	}
	if len(ts.deletedIDs) != 1 || ts.deletedIDs[0] != "acl_B" {
		t.Fatalf("deleted %v, want exactly [acl_B]", ts.deletedIDs)
	}
}

// TestACLRevoke_ByID_DeletesCorrectRow confirms revoke by ag_ ID still works.
func TestACLRevoke_ByID_DeletesCorrectRow(t *testing.T) {
	entries := []api.ACLEntrySummary{
		{ID: "acl_A", CallerTokenID: "caller_x", AgentID: "ag_A", Username: "derek"},
		{ID: "acl_B", CallerTokenID: "caller_x", AgentID: "ag_B", Username: "derek"},
	}
	ts := newACLRevokeTestServer(t, map[string]string{"ag_B": "ag_B", "ag_A": "ag_A"}, entries)

	out, err := runACLRevoke(t, ts.URL, "caller_x", "ag_B", "--as", "derek")
	if err != nil {
		t.Fatalf("revoke by id: unexpected error: %v (out=%q)", err, out)
	}
	if len(ts.deletedIDs) != 1 || ts.deletedIDs[0] != "acl_B" {
		t.Fatalf("deleted %v, want exactly [acl_B]", ts.deletedIDs)
	}
}

// TestACLRevoke_UnresolvableName_Errors confirms an unresolvable Agent name is an
// error and deletes nothing (no silent first-match delete).
func TestACLRevoke_UnresolvableName_Errors(t *testing.T) {
	entries := []api.ACLEntrySummary{
		{ID: "acl_A", CallerTokenID: "caller_x", AgentID: "ag_A", Username: "derek"},
	}
	ts := newACLRevokeTestServer(t, map[string]string{"box-a": "ag_A"}, entries)

	_, err := runACLRevoke(t, ts.URL, "caller_x", "ghost", "--as", "derek")
	if err == nil {
		t.Fatal("revoke of unresolvable agent name should error")
	}
	if len(ts.deletedIDs) != 0 {
		t.Fatalf("deleted %v, want nothing on unresolvable name", ts.deletedIDs)
	}
}
