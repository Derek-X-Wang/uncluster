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
	agents    map[string]string          // name or id → canonical agent id
	agentByID map[string]api.AgentDetail // canonical id → detail
	agentList []api.AgentDetail          // insertion order for ListAgents
	rows      []api.ACLEntrySummary
	nextID    int

	// recorded side effects, for assertions
	removedAgents   []string
	failClosedCalls []fakeFailClosedCall
	certReqs        []api.CertRequest
	createdTokens   []api.CreateTokenRequest
	revokedTokens   []string
	updatePolicies  []api.SetUpdatePolicyRequest

	// canned data returned by list/read methods
	certResp    api.CertResponse
	certEvents  []api.CertEventSummary
	tokens      []api.TokenSummary
	nextTokenID int
}

// fakeFailClosedCall records one SetAgentFailClosedAfter invocation so a test
// can assert both the target and whether the window was set or cleared (nil).
type fakeFailClosedCall struct {
	IDOrName string
	Seconds  *int64
}

func newFakeControlPlaneClient() *fakeControlPlaneClient {
	return &fakeControlPlaneClient{
		agents:    map[string]string{},
		agentByID: map[string]api.AgentDetail{},
	}
}

// registerAgent maps a name and its id to the canonical id (both resolve).
func (f *fakeControlPlaneClient) registerAgent(name, id string) {
	f.agents[name] = id
	f.agents[id] = id
}

// addAgent registers an Agent (name+id resolve) and stores its full detail so
// ListAgents / GetAgent return it in insertion order.
func (f *fakeControlPlaneClient) addAgent(ad api.AgentDetail) {
	f.registerAgent(ad.Name, ad.ID)
	f.agentByID[ad.ID] = ad
	f.agentList = append(f.agentList, ad)
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

func (f *fakeControlPlaneClient) ListAgents(context.Context) ([]api.AgentDetail, error) {
	return f.agentList, nil
}

func (f *fakeControlPlaneClient) GetAgent(_ context.Context, idOrName string) (api.AgentDetail, error) {
	id, ok := f.agents[idOrName]
	if !ok {
		return api.AgentDetail{}, fmt.Errorf("resolve agent %q: not found", idOrName)
	}
	if ad, ok := f.agentByID[id]; ok {
		return ad, nil
	}
	return api.AgentDetail{ID: id, Name: idOrName}, nil
}

func (f *fakeControlPlaneClient) RemoveAgent(_ context.Context, idOrName string) error {
	f.removedAgents = append(f.removedAgents, idOrName)
	return nil
}

func (f *fakeControlPlaneClient) SetAgentFailClosedAfter(_ context.Context, idOrName string, seconds *int64) error {
	f.failClosedCalls = append(f.failClosedCalls, fakeFailClosedCall{IDOrName: idOrName, Seconds: seconds})
	return nil
}

func (f *fakeControlPlaneClient) RequestCert(_ context.Context, req api.CertRequest) (api.CertResponse, error) {
	f.certReqs = append(f.certReqs, req)
	if f.certResp.Certificate != "" {
		return f.certResp, nil
	}
	return api.CertResponse{Certificate: "ssh-ed25519-cert-v01 fake", KeyID: "key_fake", Principal: req.Username}, nil
}

func (f *fakeControlPlaneClient) ListCertEvents(_ context.Context, q CertAuditQuery) ([]api.CertEventSummary, error) {
	var out []api.CertEventSummary
	for _, e := range f.certEvents {
		if q.Caller != "" && e.CallerTokenID != q.Caller {
			continue
		}
		if q.Agent != "" && e.TargetAgentID != q.Agent {
			continue
		}
		if q.User != "" && e.Username != q.User {
			continue
		}
		if q.Outcome != "" && e.Outcome != q.Outcome {
			continue
		}
		if q.Since > 0 && e.TS < q.Since {
			continue
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

func (f *fakeControlPlaneClient) CreateToken(_ context.Context, kind, label string) (api.CreateTokenResponse, error) {
	f.createdTokens = append(f.createdTokens, api.CreateTokenRequest{Kind: kind, Label: label})
	f.nextTokenID++
	id := fmt.Sprintf("tok_%d", f.nextTokenID)
	return api.CreateTokenResponse{ID: id, Token: "uct_" + kind + "_" + id + "_secret"}, nil
}

func (f *fakeControlPlaneClient) ListTokens(context.Context) ([]api.TokenSummary, error) {
	return f.tokens, nil
}

func (f *fakeControlPlaneClient) RevokeToken(_ context.Context, id string) error {
	f.revokedTokens = append(f.revokedTokens, id)
	return nil
}

func (f *fakeControlPlaneClient) SetUpdatePolicy(_ context.Context, req api.SetUpdatePolicyRequest) error {
	f.updatePolicies = append(f.updatePolicies, req)
	return nil
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

// TestHTTPSetAgentFailClosedAfter_NullVsValue locks the PATCH wire contract:
// clearing sends fail_closed_after: null; setting sends the integer value. A
// silent regression here (e.g. omitting the field) would change server behavior.
func TestHTTPSetAgentFailClosedAfter_NullVsValue(t *testing.T) {
	var gotPath string
	var gotBody map[string]json.RawMessage
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	client := newHTTPControlPlaneClient(ts.URL, "tok")

	secs := int64(3600)
	if err := client.SetAgentFailClosedAfter(context.Background(), "box-a", &secs); err != nil {
		t.Fatalf("set: %v", err)
	}
	if gotPath != "/v1/agents/box-a" {
		t.Errorf("path = %q, want /v1/agents/box-a", gotPath)
	}
	if string(gotBody["fail_closed_after"]) != "3600" {
		t.Errorf("set body fail_closed_after = %s, want 3600", gotBody["fail_closed_after"])
	}

	if err := client.SetAgentFailClosedAfter(context.Background(), "box-a", nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if string(gotBody["fail_closed_after"]) != "null" {
		t.Errorf("clear body fail_closed_after = %s, want null", gotBody["fail_closed_after"])
	}
}

// TestHTTPRequestCert round-trips a cert request through the adapter.
func TestHTTPRequestCert(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/certs" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req api.CertRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(api.CertResponse{
			Certificate: "cert-for-" + req.Username, KeyID: "key_1", Principal: req.Username,
		})
	}))
	t.Cleanup(ts.Close)

	client := newHTTPControlPlaneClient(ts.URL, "tok")
	resp, err := client.RequestCert(context.Background(), api.CertRequest{
		Agent: "ag_1", Username: "derek", Pubkey: "ssh-ed25519 AAAA",
	})
	if err != nil {
		t.Fatalf("RequestCert: %v", err)
	}
	if resp.Certificate != "cert-for-derek" || resp.KeyID != "key_1" {
		t.Errorf("resp = %+v, want cert-for-derek/key_1", resp)
	}
}

// TestHTTPListAgents confirms the list adapter decodes the agent slice.
func TestHTTPListAgents(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/agents" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]api.AgentDetail{{ID: "ag_1", Name: "box"}})
	}))
	t.Cleanup(ts.Close)

	client := newHTTPControlPlaneClient(ts.URL, "tok")
	agents, err := client.ListAgents(context.Background())
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 || agents[0].ID != "ag_1" || agents[0].Name != "box" {
		t.Errorf("agents = %+v, want one ag_1/box", agents)
	}
}
