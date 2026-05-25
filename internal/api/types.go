// Package api holds the wire-format structs used on both sides of the HTTP
// boundary. Kept free of third-party deps so it can be imported by both the
// server and the agent without circularity.
package api

import "time"

// --- health ---

type HealthResponse struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
}

// --- tokens ---

type CreateTokenRequest struct {
	Kind      string `json:"kind"`                 // "join" | "cli"
	Label     string `json:"label,omitempty"`
	ExpiresAt *int64 `json:"expires_at,omitempty"` // unix seconds
}

type CreateTokenResponse struct {
	ID    string `json:"id"`
	Token string `json:"token"` // plaintext, shown once
}

type TokenSummary struct {
	ID        string  `json:"id"`
	Kind      string  `json:"kind"`
	Label     string  `json:"label,omitempty"`
	NodeID    *string `json:"node_id,omitempty"`
	CreatedAt int64   `json:"created_at"`
	ExpiresAt *int64  `json:"expires_at,omitempty"`
	UsedAt    *int64  `json:"used_at,omitempty"`
	RevokedAt *int64  `json:"revoked_at,omitempty"`
}

// --- nodes ---

type NodeSummary struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	CreatedAt  int64           `json:"created_at"`
	LastSeenAt *int64          `json:"last_seen_at,omitempty"`
	Metadata   map[string]any  `json:"metadata"`
}

// --- agent: register ---

type AgentRegisterRequest struct {
	JoinToken string         `json:"join_token"`
	Name      string         `json:"name"`
	Metadata  map[string]any `json:"metadata"`
}

// ExpectedPaths holds the canonical SSH-related file paths the Agent should
// manage on disk. Values are resolved by the Control plane at enrollment time
// based on the registering platform (linux/darwin vs. windows).
type ExpectedPaths struct {
	CAPubkey      string `json:"ca_pubkey"`
	SSHDropIn     string `json:"sshd_drop_in"`
	PrincipalsDir string `json:"principals_dir"`
}

// AgentRegisterResponse is the V2 enrollment response from the Control plane.
// The agent_token is plaintext and shown exactly once; the caller must persist it.
type AgentRegisterResponse struct {
	AgentID        string        `json:"agent_id"`
	AgentToken     string        `json:"agent_token"`              // plaintext, shown once
	CAPubkey       string        `json:"ca_pubkey"`                // authorized_keys-format line
	ServerHTTPSPin string        `json:"server_https_pin,omitempty"` // sha256:<hex>; empty if not pinned
	ExpectedPaths  ExpectedPaths `json:"expected_paths"`
}

// --- agent: heartbeat ---

// HeartbeatRequest is the V1 heartbeat shape (kept until S11).
type HeartbeatRequest struct {
	Metadata map[string]any `json:"metadata"`
}

// HeartbeatResponse is the V1 heartbeat response (kept until S11).
type HeartbeatResponse struct {
	CancelTaskIDs []string `json:"cancel_task_ids,omitempty"`
}

// --- agent: V2 heartbeat ---

// AgentEndpoint is one subnet→address binding the agent observed.
type AgentEndpoint struct {
	Subnet  string `json:"subnet"`  // e.g. "home-tailnet", "home-lan", "home-tailnet@100.64.1.1"
	Address string `json:"address"` // IP address on that subnet
}

// AgentPolicyState is the agent's last known policy synchronisation status.
type AgentPolicyState struct {
	DesiredVersion  *int64  `json:"desired_version"`            // version the server last pushed; null if none yet
	AppliedVersion  int64   `json:"applied_version"`            // last version the agent successfully applied
	AppliedHash     string  `json:"applied_hash"`               // blake3:<hex> of the applied policy
	LastApplyStatus string  `json:"last_apply_status"`          // "ok" | "failed"
	LastApplyError  *string `json:"last_apply_error,omitempty"` // non-nil on failure
	LastApplyAt     int64   `json:"last_apply_at"`              // unix seconds
}

// AgentHealthCheck is one structured health check item.
type AgentHealthCheck struct {
	Component string  `json:"component"` // "sshd", "ca_pubkey", "principals", ...
	Check     string  `json:"check"`     // "running", "config_drop_in", "present", "dir_writable"
	State     string  `json:"state"`     // "ok" | "warn" | "fail" | "unknown"
	ErrorCode *string `json:"error_code,omitempty"`
	Message   *string `json:"message,omitempty"`
}

// V2HeartbeatRequest is the V2 typed state-sync envelope.
type V2HeartbeatRequest struct {
	AgentID      string             `json:"agent_id"`
	AgentVersion string             `json:"agent_version"`
	ObservedAt   int64              `json:"observed_at"` // unix seconds
	Endpoints    []AgentEndpoint    `json:"endpoints"`
	PolicyState  AgentPolicyState   `json:"policy_state"`
	Health       []AgentHealthCheck `json:"health"`
	Metrics      map[string]any     `json:"metrics,omitempty"` // best-effort; absent = ok
}

// V2HeartbeatResponse is the server's response to a V2 heartbeat.
type V2HeartbeatResponse struct {
	AckTS      int64            `json:"ack_ts"`      // server's unix timestamp acknowledging the beat
	ServerTime int64            `json:"server_time"` // server wall-clock unix seconds
	Policy     *PolicyPayload   `json:"policy"`      // null when policy matches applied_hash
	Commands   []any            `json:"commands"`    // empty until S8b
}

// --- ACL ---

// PolicyPrincipal is one user + set of caller_token_ids permitted to SSH as that user.
type PolicyPrincipal struct {
	Username       string   `json:"username"`
	CallerTokenIDs []string `json:"caller_token_ids"`
}

// PolicyPayload is the full policy snapshot sent in a heartbeat response
// when the agent's applied_hash does not match the server's current hash.
type PolicyPayload struct {
	Version    int64             `json:"version"`
	Hash       string            `json:"hash"`     // "blake3:<hex>" or ""
	Principals []PolicyPrincipal `json:"principals"`
}

// ACLEntrySummary is a single ACL row as returned by the API.
type ACLEntrySummary struct {
	ID            string `json:"id"`
	CallerTokenID string `json:"caller_token_id"`
	AgentID       string `json:"agent_id"`
	Username      string `json:"username"`
	CreatedAt     int64  `json:"created_at"`
	CreatedBy     *string `json:"created_by,omitempty"`
}

// CreateACLRequest is the body for POST /v1/acl.
type CreateACLRequest struct {
	Caller   string `json:"caller"`   // caller token id or name
	Agent    string `json:"agent"`    // agent id or name
	Username string `json:"username"` // SSH username
}

// CreateACLResponse is the body returned by POST /v1/acl.
type CreateACLResponse struct {
	ACLEntrySummary
}

// --- agents list / detail ---

// AgentEndpointSummary is one subnet→address binding in the agent detail response.
type AgentEndpointSummary struct {
	Subnet  string `json:"subnet"`
	Address string `json:"address"`
}

// AgentDetail is the full agent record returned by GET /v1/agents/{id}.
type AgentDetail struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Status       string                 `json:"status"`
	AgentVersion string                 `json:"agent_version"`
	CreatedAt    int64                  `json:"created_at"`
	LastSeenAt   *int64                 `json:"last_seen_at,omitempty"`
	Endpoints    []AgentEndpointSummary `json:"endpoints"`
}

// --- cert signing ---

// CertRequest is the body for POST /v1/certs.
type CertRequest struct {
	Agent      string `json:"agent"`       // agent id or name
	Username   string `json:"username"`    // SSH principal
	Pubkey     string `json:"pubkey"`      // authorized_keys-format user public key
	TTLSeconds int    `json:"ttl_seconds"` // 0 → default (300s); max 900s
}

// CertResponse is the response from POST /v1/certs.
type CertResponse struct {
	Certificate string `json:"certificate"` // authorized_keys-format cert
	KeyID       string `json:"key_id"`
	Principal   string `json:"principal"`
	Serial      uint64 `json:"serial"`
	ValidAfter  int64  `json:"valid_after"`
	ValidBefore int64  `json:"valid_before"`
}

// --- agent: next-task ---

type NextTaskResponse struct {
	TaskID  string `json:"task_id"`
	Command string `json:"command"`
}

// --- agent: chunks / complete ---

type ChunkUploadRequest struct {
	Stream string `json:"stream"` // "stdout" | "stderr"
	Data   []byte `json:"data"`   // JSON marshals as base64
}

type ChunkUploadResponse struct {
	Truncated     bool     `json:"truncated,omitempty"`
	CancelTaskIDs []string `json:"cancel_task_ids,omitempty"`
}

type CompleteRequest struct {
	ExitCode int `json:"exit_code"`
}

// --- tasks ---

type CreateTaskRequest struct {
	Node    string `json:"node"` // id or name
	Command string `json:"command"`
}

type CreateTaskResponse struct {
	TaskID string `json:"task_id"`
}

type TaskDetail struct {
	ID              string `json:"id"`
	NodeID          string `json:"node_id"`
	Command         string `json:"command"`
	Status          string `json:"status"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	CreatedAt       int64  `json:"created_at"`
	StartedAt       *int64 `json:"started_at,omitempty"`
	FinishedAt      *int64 `json:"finished_at,omitempty"`
	OutputBytes     int64  `json:"output_bytes"`
	OutputTruncated bool   `json:"output_truncated"`
}

type ChunkOut struct {
	Stream    string `json:"stream"`
	Seq       int64  `json:"seq"`
	Data      []byte `json:"data"`
	CreatedAt int64  `json:"created_at"`
}

type ChunksResponse struct {
	Chunks []ChunkOut `json:"chunks"`
}

// --- errors ---

type ErrorResponse struct {
	Error string `json:"error"`
}

// Helper — convert store time fields to JSON-friendly *int64 seconds.
func TimePtr(t *time.Time) *int64 {
	if t == nil {
		return nil
	}
	v := t.Unix()
	return &v
}
