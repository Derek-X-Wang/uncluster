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

type HeartbeatRequest struct {
	Metadata map[string]any `json:"metadata"`
}

type HeartbeatResponse struct {
	CancelTaskIDs []string `json:"cancel_task_ids,omitempty"`
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
