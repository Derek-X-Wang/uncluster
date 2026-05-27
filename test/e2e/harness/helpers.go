package harness

import (
	"context"
	"fmt"
	"net/url"
)

// MintJoinToken POSTs /v1/tokens with kind=join and returns the plaintext
// token. The Client must already hold a caller token with admin auth.
//
// Wire-format note: the response shape mirrors api.CreateTokenResponse,
// duplicated here so the harness has no compile-time coupling to internal/api.
func (c *Client) MintJoinToken(ctx context.Context, label string) (string, error) {
	body := map[string]any{
		"kind":  "join",
		"label": label,
	}
	var resp struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := c.Do(ctx, "POST", "/v1/tokens", body, &resp); err != nil {
		return "", fmt.Errorf("mint join token: %w", err)
	}
	return resp.Token, nil
}

// MintCallerToken POSTs /v1/tokens with kind=caller and returns the plaintext
// token. Used by T1b/T3b when exercising multiple Caller identities.
func (c *Client) MintCallerToken(ctx context.Context, label string) (string, error) {
	body := map[string]any{
		"kind":  "caller",
		"label": label,
	}
	var resp struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := c.Do(ctx, "POST", "/v1/tokens", body, &resp); err != nil {
		return "", fmt.Errorf("mint caller token: %w", err)
	}
	return resp.Token, nil
}

// EnrollAgent POSTs /v1/agents/register with the join token + name. Returns
// the agent_id assigned by the Control plane. The Client must NOT carry a
// caller token here — registration is open and uses the join token only.
func (c *Client) EnrollAgent(ctx context.Context, joinToken, name string) (string, error) {
	body := map[string]any{
		"join_token": joinToken,
		"name":       name,
		"metadata":   map[string]any{},
	}
	var resp struct {
		AgentID    string `json:"agent_id"`
		AgentToken string `json:"agent_token"`
	}
	if err := c.Do(ctx, "POST", "/v1/agents/register", body, &resp); err != nil {
		return "", fmt.Errorf("enroll agent: %w", err)
	}
	return resp.AgentID, nil
}

// GrantACL POSTs /v1/acl to allow a Caller token to SSH into an Agent as
// the given Unix username. One row per (caller, agent, username) tuple —
// to grant multiple usernames, call this once per username (the server
// shape is intentionally narrow; see internal/api/types.go).
//
// Returns the new ACL row's id so the caller can later RevokeACL.
func (c *Client) GrantACL(ctx context.Context, callerTokenID, agent, username string) (string, error) {
	body := map[string]any{
		"caller":   callerTokenID,
		"agent":    agent,
		"username": username,
	}
	var resp struct {
		ID            string `json:"id"`
		CallerTokenID string `json:"caller_token_id"`
		AgentID       string `json:"agent_id"`
		Username      string `json:"username"`
	}
	if err := c.Do(ctx, "POST", "/v1/acl", body, &resp); err != nil {
		return "", fmt.Errorf("grant acl: %w", err)
	}
	return resp.ID, nil
}

// RequestCert POSTs /v1/certs and returns the issued cert in
// authorized_keys-format. The Client must carry a caller token that has been
// granted ACL access to the agent.
func (c *Client) RequestCert(ctx context.Context, agent, username, pubkey string, ttlSeconds int) (string, error) {
	body := map[string]any{
		"agent":       agent,
		"username":    username,
		"pubkey":      pubkey,
		"ttl_seconds": ttlSeconds,
	}
	var resp struct {
		Certificate string `json:"certificate"`
		KeyID       string `json:"key_id"`
		Principal   string `json:"principal"`
		Serial      uint64 `json:"serial"`
	}
	if err := c.Do(ctx, "POST", "/v1/certs", body, &resp); err != nil {
		return "", fmt.Errorf("request cert: %w", err)
	}
	return resp.Certificate, nil
}

// RevokeToken DELETEs /v1/tokens/<id>. Used to test 401 propagation.
func (c *Client) RevokeToken(ctx context.Context, tokenID string) error {
	if err := c.Do(ctx, "DELETE", "/v1/tokens/"+tokenID, nil, nil); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

// DeprovisionAgent DELETEs /v1/agents/<id-or-name>. Drives the deprovision
// flow that wipes principals on the Agent (heartbeat sees 410 Gone).
func (c *Client) DeprovisionAgent(ctx context.Context, agent string) error {
	if err := c.Do(ctx, "DELETE", "/v1/agents/"+agent, nil, nil); err != nil {
		return fmt.Errorf("deprovision agent: %w", err)
	}
	return nil
}

// RevokeACL DELETEs /v1/acl/<id>. The id is the value returned by GrantACL.
func (c *Client) RevokeACL(ctx context.Context, aclID string) error {
	if err := c.Do(ctx, "DELETE", "/v1/acl/"+aclID, nil, nil); err != nil {
		return fmt.Errorf("revoke acl: %w", err)
	}
	return nil
}

// CertEvent mirrors api.CertEventSummary but local to the harness so test
// code does not depend on internal/api.
type CertEvent struct {
	RequestID     string `json:"request_id"`
	TS            int64  `json:"ts"`
	CallerTokenID string `json:"caller_token_id"`
	TargetAgentID string `json:"target_agent_id,omitempty"`
	Username      string `json:"username,omitempty"`
	CertPrincipal string `json:"cert_principal,omitempty"`
	Outcome       string `json:"outcome"`
	DenialReason  string `json:"denial_reason,omitempty"`
}

// ListCertEvents GETs /v1/audit/certs. Optional `filters` map appends query
// params (caller, agent, user, outcome, since, limit).
//
// The query is built and url-encoded here rather than concatenated into the
// path passed to Client.Do, because Client.Do uses url.JoinPath which
// percent-encodes `?` (treating it as a literal path char).
func (c *Client) ListCertEvents(ctx context.Context, filters map[string]string) ([]CertEvent, error) {
	q := url.Values{}
	for k, v := range filters {
		q.Set(k, v)
	}
	path := "/v1/audit/certs"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var resp []CertEvent
	if err := c.doRaw(ctx, "GET", path, nil, &resp); err != nil {
		return nil, fmt.Errorf("list cert events: %w", err)
	}
	return resp, nil
}
