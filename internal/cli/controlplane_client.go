package cli

import (
	"context"
	"fmt"
	"net/url"

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

// newConfiguredControlPlaneClient loads the CLI config, validates it, and
// returns the HTTP adapter. Shared by every acl command's RunE so the
// config-load + validation error surface is defined once.
func newConfiguredControlPlaneClient() (ControlPlaneClient, error) {
	cfg, err := LoadCLIConfig()
	if err != nil {
		return nil, err
	}
	if cfg.Server == "" || cfg.Token == "" {
		return nil, fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
	}
	return newHTTPControlPlaneClient(cfg.Server, cfg.Token), nil
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
