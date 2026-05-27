package harness

import (
	"context"
	"fmt"
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
// the given Unix usernames. Used by T1b cert-flow scenarios.
func (c *Client) GrantACL(ctx context.Context, callerTokenID, agent string, usernames []string) error {
	body := map[string]any{
		"caller_token_id": callerTokenID,
		"agent":           agent,
		"usernames":       usernames,
	}
	if err := c.Do(ctx, "POST", "/v1/acl", body, nil); err != nil {
		return fmt.Errorf("grant acl: %w", err)
	}
	return nil
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
