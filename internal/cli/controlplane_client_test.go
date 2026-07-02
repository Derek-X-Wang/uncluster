package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// fakeControlPlaneClient is the in-memory second adapter of the ControlPlaneClient
// seam (the first is httpControlPlaneClient). It models agents (name/id →
// canonical id) and ACL rows so command logic can be exercised without HTTP. It
// shares the production selectACLEntry decision, so a revoke-by-name test here
// exercises the same #141 selection contract the HTTP adapter uses.
type fakeControlPlaneClient struct {
	agents map[string]string // name or id → canonical agent id
	rows   []api.ACLEntrySummary
	nextID int
}

func newFakeControlPlaneClient() *fakeControlPlaneClient {
	return &fakeControlPlaneClient{agents: map[string]string{}}
}

// registerAgent maps a name and its id to the canonical id (both resolve).
func (f *fakeControlPlaneClient) registerAgent(name, id string) {
	f.agents[name] = id
	f.agents[id] = id
}

func (f *fakeControlPlaneClient) GrantACL(_ context.Context, caller, agent, username string) (api.ACLEntrySummary, error) {
	agentID, ok := f.agents[agent]
	if !ok {
		return api.ACLEntrySummary{}, fmt.Errorf("resolve agent %q: not found", agent)
	}
	f.nextID++
	e := api.ACLEntrySummary{
		ID:            fmt.Sprintf("acl_%d", f.nextID),
		CallerTokenID: caller,
		AgentID:       agentID,
		Username:      username,
	}
	f.rows = append(f.rows, e)
	return e, nil
}

func (f *fakeControlPlaneClient) RevokeACL(_ context.Context, caller, agent, username string) (api.ACLEntrySummary, error) {
	agentID, ok := f.agents[agent]
	if !ok {
		return api.ACLEntrySummary{}, fmt.Errorf("resolve agent %q: not found", agent)
	}
	var callerRows []api.ACLEntrySummary
	for _, r := range f.rows {
		if r.CallerTokenID == caller {
			callerRows = append(callerRows, r)
		}
	}
	entry, err := selectACLEntry(callerRows, agentID, username)
	if err != nil {
		return api.ACLEntrySummary{}, fmt.Errorf("%w (caller=%s agent=%s)", err, caller, agent)
	}
	for i, r := range f.rows {
		if r.ID == entry.ID {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			break
		}
	}
	return entry, nil
}

func (f *fakeControlPlaneClient) ListACL(_ context.Context, callerFilter, agentFilter string) ([]api.ACLEntrySummary, error) {
	var out []api.ACLEntrySummary
	for _, r := range f.rows {
		if callerFilter != "" && r.CallerTokenID != callerFilter {
			continue
		}
		if agentFilter != "" && r.AgentID != agentFilter {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// static assertion: both adapters satisfy the seam.
var (
	_ ControlPlaneClient = (*httpControlPlaneClient)(nil)
	_ ControlPlaneClient = (*fakeControlPlaneClient)(nil)
)

// aclHTTPTestServer builds an httptest server for the HTTP adapter tests:
// resolves agent names, serves ACL rows, and records deleted ids.
func aclHTTPTestServer(t *testing.T, resolvable map[string]string, entries []api.ACLEntrySummary, deleted *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/agents/"):
			name := strings.TrimPrefix(r.URL.Path, "/v1/agents/")
			id, ok := resolvable[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(api.AgentDetail{ID: id, Name: name})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/acl":
			_ = json.NewEncoder(w).Encode(entries)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/acl/"):
			*deleted = append(*deleted, strings.TrimPrefix(r.URL.Path, "/v1/acl/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestHTTPRevokeACL_ByName_DeletesCorrectRow is the #141 regression at the HTTP
// wire: the adapter resolves the agent name to its id and deletes only that
// agent's row, even when the caller holds the same username on two agents.
func TestHTTPRevokeACL_ByName_DeletesCorrectRow(t *testing.T) {
	entries := []api.ACLEntrySummary{
		{ID: "acl_A", CallerTokenID: "caller_x", AgentID: "ag_A", Username: "derek"},
		{ID: "acl_B", CallerTokenID: "caller_x", AgentID: "ag_B", Username: "derek"},
	}
	var deleted []string
	ts := aclHTTPTestServer(t, map[string]string{"box-a": "ag_A", "box-b": "ag_B"}, entries, &deleted)

	client := newHTTPControlPlaneClient(ts.URL, "tok")
	entry, err := client.RevokeACL(context.Background(), "caller_x", "box-b", "derek")
	if err != nil {
		t.Fatalf("RevokeACL by name: %v", err)
	}
	if entry.ID != "acl_B" {
		t.Errorf("revoked entry id = %q, want acl_B", entry.ID)
	}
	if len(deleted) != 1 || deleted[0] != "acl_B" {
		t.Fatalf("deleted %v, want exactly [acl_B]", deleted)
	}
}

// TestHTTPRevokeACL_UnresolvableName_Errors confirms the HTTP adapter errors on
// an unresolvable name and deletes nothing.
func TestHTTPRevokeACL_UnresolvableName_Errors(t *testing.T) {
	entries := []api.ACLEntrySummary{
		{ID: "acl_A", CallerTokenID: "caller_x", AgentID: "ag_A", Username: "derek"},
	}
	var deleted []string
	ts := aclHTTPTestServer(t, map[string]string{"box-a": "ag_A"}, entries, &deleted)

	client := newHTTPControlPlaneClient(ts.URL, "tok")
	if _, err := client.RevokeACL(context.Background(), "caller_x", "ghost", "derek"); err == nil {
		t.Fatal("RevokeACL of unresolvable agent name should error")
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted %v on unresolvable name, want none", deleted)
	}
}

// TestHTTPGrantACL_PostsAndReturnsEntry confirms the grant adapter round-trips.
func TestHTTPGrantACL_PostsAndReturnsEntry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/acl" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req api.CreateACLRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(api.ACLEntrySummary{
			ID: "acl_new", CallerTokenID: req.Caller, AgentID: "ag_" + req.Agent, Username: req.Username,
		})
	}))
	t.Cleanup(ts.Close)

	client := newHTTPControlPlaneClient(ts.URL, "tok")
	entry, err := client.GrantACL(context.Background(), "caller_x", "box", "derek")
	if err != nil {
		t.Fatalf("GrantACL: %v", err)
	}
	if entry.ID != "acl_new" || entry.Username != "derek" {
		t.Errorf("GrantACL entry = %+v, want id=acl_new username=derek", entry)
	}
}
