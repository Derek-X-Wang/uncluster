package cli

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// ControlPlaneClient is the typed seam over the Uncluster Control plane HTTP API
// used by the operator CLI. Commands depend on this interface, not on raw HTTP,
// so their logic is testable against an in-memory fake instead of an httptest
// server, and so a bug can't hide in an untested command closure (the class of
// bug #141 was).
//
// #148 introduces the ACL methods; later slices (#149) extend this interface
// with the ssh/agents/audit/token/update endpoints. Two adapters implement it:
// the real HTTP client (httpControlPlaneClient) and an in-memory fake used in
// tests — a real seam, not a single-adapter indirection.
//
// The Agent-side client is deliberately NOT part of this seam: its
// 401→unauthorized / 410→revoked semantics are role-specific and must survive
// (counsel constraint). Likewise the e2e harness keeps its own decoupled client.
type ControlPlaneClient interface {
	// GrantACL creates an ACL row allowing caller to SSH to agent as username.
	GrantACL(ctx context.Context, caller, agent, username string) (api.ACLEntrySummary, error)
	// RevokeACL removes the ACL row for (caller, agent, username) and returns it.
	// agent may be an id or a name; the name is resolved to its canonical Agent
	// ID before matching so the correct row is deleted even when the caller holds
	// the same username on more than one agent (#141).
	RevokeACL(ctx context.Context, caller, agent, username string) (api.ACLEntrySummary, error)
	// ListACL returns ACL rows, optionally filtered by caller and/or agent id.
	ListACL(ctx context.Context, callerFilter, agentFilter string) ([]api.ACLEntrySummary, error)

	// --- agents (#149) ---

	// ListAgents returns every registered Agent.
	ListAgents(ctx context.Context) ([]api.AgentDetail, error)
	// GetAgent resolves an Agent by id or name to its full detail record.
	GetAgent(ctx context.Context, idOrName string) (api.AgentDetail, error)
	// RemoveAgent revokes and deletes an Agent by id or name.
	RemoveAgent(ctx context.Context, idOrName string) error
	// SetAgentFailClosedAfter updates the Agent's fail-closed window. A nil
	// seconds clears it (sends fail_closed_after: null); a non-nil value sets it.
	SetAgentFailClosedAfter(ctx context.Context, idOrName string, seconds *int64) error

	// --- certs / ssh (#149) ---

	// RequestCert asks the Control plane to sign a short-lived SSH certificate.
	RequestCert(ctx context.Context, req api.CertRequest) (api.CertResponse, error)

	// --- audit (#149) ---

	// ListCertEvents returns cert issuance Audit events matching the query.
	ListCertEvents(ctx context.Context, q CertAuditQuery) ([]api.CertEventSummary, error)

	// --- tokens (#149) ---

	// CreateToken mints a token of the given kind; the plaintext is returned once.
	CreateToken(ctx context.Context, kind, label string) (api.CreateTokenResponse, error)
	// ListTokens returns token summaries (never plaintext secrets).
	ListTokens(ctx context.Context) ([]api.TokenSummary, error)
	// RevokeToken revokes a token by id.
	RevokeToken(ctx context.Context, id string) error

	// --- self-update policy (#149) ---

	// SetUpdatePolicy sets the Control plane's expected agent version + asset
	// templates that drive agent self-update.
	SetUpdatePolicy(ctx context.Context, req api.SetUpdatePolicyRequest) error
}

// CertAuditQuery is the typed filter for ListCertEvents. Empty string / zero
// fields are omitted from the wire query. Building the query string with proper
// URL value encoding lives in the HTTP adapter so command bodies carry no query
// encoding (#149).
type CertAuditQuery struct {
	Caller  string
	Agent   string
	User    string
	Outcome string
	Since   int64 // unix seconds; 0 = omit
	Limit   int   // 0 = omit
}

// httpControlPlaneClient is the production adapter: it speaks the real HTTP API
// through the generic Client.
type httpControlPlaneClient struct {
	c *Client
}

// newHTTPControlPlaneClient builds the HTTP adapter over the generic Client.
func newHTTPControlPlaneClient(baseURL, token string) *httpControlPlaneClient {
	return &httpControlPlaneClient{c: NewClient(baseURL, token)}
}

// errNotConfigured is the single "CLI not configured" error used by every
// Caller-facing command through loadConfiguredCLI. Before #149 two different
// messages existed (`config init` vs `config set …`) and the token ls/revoke
// subcommands skipped the guard entirely; this is now the one guard message.
var errNotConfigured = fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")

// loadConfiguredCLI loads the CLI config, applies the server+token guard, and
// returns both the parsed config (for commands that also need SSH fields or
// subnets, e.g. `ssh` and `agents ls`) and the HTTP Control-plane adapter. The
// guard has exactly one implementation and lives here.
func loadConfiguredCLI() (CLIConfig, ControlPlaneClient, error) {
	cfg, err := LoadCLIConfig()
	if err != nil {
		return CLIConfig{}, nil, err
	}
	if cfg.Server == "" || cfg.Token == "" {
		return CLIConfig{}, nil, errNotConfigured
	}
	return cfg, newHTTPControlPlaneClient(cfg.Server, cfg.Token), nil
}

// newConfiguredControlPlaneClient returns just the HTTP adapter for the common
// case where a command needs only the client, not the SSH-specific config.
func newConfiguredControlPlaneClient() (ControlPlaneClient, error) {
	_, client, err := loadConfiguredCLI()
	return client, err
}

func (h *httpControlPlaneClient) GrantACL(ctx context.Context, caller, agent, username string) (api.ACLEntrySummary, error) {
	var entry api.ACLEntrySummary
	err := h.c.Do(ctx, "POST", "/v1/acl", api.CreateACLRequest{
		Caller:   caller,
		Agent:    agent,
		Username: username,
	}, &entry)
	return entry, err
}

func (h *httpControlPlaneClient) RevokeACL(ctx context.Context, caller, agent, username string) (api.ACLEntrySummary, error) {
	// Resolve the agent name/id to its canonical Agent ID first — the same
	// resolution the grant path performs server-side. Without it, matching by
	// name across the caller's rows deletes the first same-caller+username row
	// across ALL agents, which can revoke the wrong Agent's access (#141). An
	// unresolvable name is an error, never a silent first-match delete.
	var ad api.AgentDetail
	if err := h.c.Do(ctx, "GET", "/v1/agents/"+agent, nil, &ad); err != nil {
		return api.ACLEntrySummary{}, fmt.Errorf("resolve agent %q: %w", agent, err)
	}
	q := url.Values{}
	q.Set("caller", caller)
	var entries []api.ACLEntrySummary
	if err := h.c.Do(ctx, "GET", "/v1/acl?"+q.Encode(), nil, &entries); err != nil {
		return api.ACLEntrySummary{}, err
	}
	entry, err := selectACLEntry(entries, ad.ID, username)
	if err != nil {
		return api.ACLEntrySummary{}, fmt.Errorf("%w (caller=%s agent=%s)", err, caller, agent)
	}
	if err := h.c.Do(ctx, "DELETE", "/v1/acl/"+entry.ID, nil, nil); err != nil {
		return api.ACLEntrySummary{}, err
	}
	return entry, nil
}

func (h *httpControlPlaneClient) ListACL(ctx context.Context, callerFilter, agentFilter string) ([]api.ACLEntrySummary, error) {
	q := url.Values{}
	if callerFilter != "" {
		q.Set("caller", callerFilter)
	}
	if agentFilter != "" {
		q.Set("agent", agentFilter)
	}
	path := "/v1/acl"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var entries []api.ACLEntrySummary
	err := h.c.Do(ctx, "GET", path, nil, &entries)
	return entries, err
}

func (h *httpControlPlaneClient) ListAgents(ctx context.Context) ([]api.AgentDetail, error) {
	var agents []api.AgentDetail
	err := h.c.Do(ctx, "GET", "/v1/agents", nil, &agents)
	return agents, err
}

func (h *httpControlPlaneClient) GetAgent(ctx context.Context, idOrName string) (api.AgentDetail, error) {
	var ad api.AgentDetail
	err := h.c.Do(ctx, "GET", "/v1/agents/"+idOrName, nil, &ad)
	return ad, err
}

func (h *httpControlPlaneClient) RemoveAgent(ctx context.Context, idOrName string) error {
	return h.c.Do(ctx, "DELETE", "/v1/agents/"+idOrName, nil, nil)
}

func (h *httpControlPlaneClient) SetAgentFailClosedAfter(ctx context.Context, idOrName string, seconds *int64) error {
	// A nil *int64 marshals to JSON null, clearing the window; a non-nil value
	// sets it. Sending the field either way is the wire contract for PATCH.
	body := map[string]any{"fail_closed_after": seconds}
	return h.c.Do(ctx, "PATCH", "/v1/agents/"+idOrName, body, nil)
}

func (h *httpControlPlaneClient) RequestCert(ctx context.Context, req api.CertRequest) (api.CertResponse, error) {
	var resp api.CertResponse
	err := h.c.Do(ctx, "POST", "/v1/certs", req, &resp)
	return resp, err
}

func (h *httpControlPlaneClient) ListCertEvents(ctx context.Context, q CertAuditQuery) ([]api.CertEventSummary, error) {
	vals := url.Values{}
	if q.Caller != "" {
		vals.Set("caller", q.Caller)
	}
	if q.Agent != "" {
		vals.Set("agent", q.Agent)
	}
	if q.User != "" {
		vals.Set("user", q.User)
	}
	if q.Outcome != "" {
		vals.Set("outcome", q.Outcome)
	}
	if q.Since > 0 {
		vals.Set("since", strconv.FormatInt(q.Since, 10))
	}
	if q.Limit > 0 {
		vals.Set("limit", strconv.Itoa(q.Limit))
	}
	path := "/v1/audit/certs"
	if len(vals) > 0 {
		path += "?" + vals.Encode()
	}
	var events []api.CertEventSummary
	err := h.c.Do(ctx, "GET", path, nil, &events)
	return events, err
}

func (h *httpControlPlaneClient) CreateToken(ctx context.Context, kind, label string) (api.CreateTokenResponse, error) {
	var out api.CreateTokenResponse
	err := h.c.Do(ctx, "POST", "/v1/tokens", api.CreateTokenRequest{Kind: kind, Label: label}, &out)
	return out, err
}

func (h *httpControlPlaneClient) ListTokens(ctx context.Context) ([]api.TokenSummary, error) {
	var out []api.TokenSummary
	err := h.c.Do(ctx, "GET", "/v1/tokens", nil, &out)
	return out, err
}

func (h *httpControlPlaneClient) RevokeToken(ctx context.Context, id string) error {
	return h.c.Do(ctx, "DELETE", "/v1/tokens/"+id, nil, nil)
}

func (h *httpControlPlaneClient) SetUpdatePolicy(ctx context.Context, req api.SetUpdatePolicyRequest) error {
	return h.c.Do(ctx, "POST", "/v1/server/update", req, nil)
}

// selectACLEntry returns the ACL row matching both agentID and username. The
// agentID must already be the canonical Agent ID (resolved from a name via the
// control plane); matching on the resolved ID — not on the raw name argument —
// is what keeps revoke from deleting a different Agent's row when a Caller holds
// the same username on more than one Agent (#141). It errors when no row matches.
// Shared by the HTTP adapter and the in-memory fake so both make the same
// selection decision.
func selectACLEntry(entries []api.ACLEntrySummary, agentID, username string) (api.ACLEntrySummary, error) {
	for _, e := range entries {
		if e.AgentID == agentID && e.Username == username {
			return e, nil
		}
	}
	return api.ACLEntrySummary{}, fmt.Errorf("no ACL entry found for agent=%s username=%s", agentID, username)
}
