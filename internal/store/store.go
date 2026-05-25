// Package store defines the persistence boundary for the control plane.
// A concrete impl lives in sqlite.go; future impls (Postgres, DynamoDB) can
// replace it without touching handlers.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound       = errors.New("store: not found")
	ErrNameTaken      = errors.New("store: node name already in use")
	ErrAgentNameTaken = errors.New("store: agent name already in use")
	ErrTokenUsed      = errors.New("store: token already used")
	ErrTokenExpired   = errors.New("store: token expired")
	ErrTokenRevoked   = errors.New("store: token revoked")
	ErrNotClaimable   = errors.New("store: task is not claimable")
	ErrTaskCompleted  = errors.New("store: task already completed")
)

type NodeStatus string

const (
	NodeOnline  NodeStatus = "online"
	NodeOffline NodeStatus = "offline"
	NodeRevoked NodeStatus = "revoked"
)

// AgentStatus mirrors NodeStatus for the V2 agents table.
type AgentStatus string

const (
	AgentOnline  AgentStatus = "online"
	AgentOffline AgentStatus = "offline"
	AgentRevoked AgentStatus = "revoked"
)

type TaskStatus string

const (
	TaskPending    TaskStatus = "pending"
	TaskRunning    TaskStatus = "running"
	TaskSucceeded  TaskStatus = "succeeded"
	TaskFailed     TaskStatus = "failed"
	TaskCancelling TaskStatus = "cancelling"
	TaskCancelled  TaskStatus = "cancelled"
)

type TokenKind string

const (
	TokenJoin   TokenKind = "join"
	TokenAgent  TokenKind = "agent"
	TokenCLI    TokenKind = "cli"    // V1; retained until S11
	TokenCaller TokenKind = "caller" // V2 — Caller token (replaces CLI)
)

type Node struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	LastSeenAt *time.Time
	Status     NodeStatus
	Metadata   string // JSON blob (free-form)
}

// Agent is the V2 enrollment record. Created when an Agent registers via
// POST /v1/agent/register; linked to its agent token via the tokens table.
type Agent struct {
	ID           string
	Name         string
	CreatedAt    time.Time
	LastSeenAt   *time.Time
	Status       AgentStatus
	AgentVersion string
}

// AgentPolicyState is the last observed policy synchronisation state reported
// by the agent via V2 heartbeat. One row per agent (upserted on each beat).
type AgentPolicyState struct {
	AgentID         string
	DesiredVersion  *int64
	AppliedVersion  int64
	AppliedHash     string
	LastApplyStatus string
	LastApplyError  *string
	LastApplyAt     time.Time
	UpdatedAt       time.Time
}

// UpsertAgentPolicyStateParams holds values for upserting an agent's policy state.
type UpsertAgentPolicyStateParams struct {
	AgentID         string
	DesiredVersion  *int64
	AppliedVersion  int64
	AppliedHash     string
	LastApplyStatus string
	LastApplyError  *string
	LastApplyAt     time.Time
}

type Token struct {
	ID         string
	Kind       TokenKind
	NodeID     *string // V1: set for node-agent tokens
	AgentID    *string // V2: set for V2 agent tokens
	SecretHash string
	Label      string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	UsedAt     *time.Time
	RevokedAt  *time.Time
}

type Task struct {
	ID              string
	NodeID          string
	Command         string
	Status          TaskStatus
	ExitCode        *int
	CreatedAt       time.Time
	StartedAt       *time.Time
	FinishedAt      *time.Time
	OutputBytes     int64
	OutputTruncated bool
	CreatedBy       *string
}

type Chunk struct {
	TaskID    string
	Stream    string // "stdout" | "stderr"
	Seq       int64
	Data      []byte
	CreatedAt time.Time
}

type NewTokenParams struct {
	ID         string // if empty, the store generates one
	Kind       TokenKind
	NodeID     *string  // V1: link to nodes table
	AgentID    *string  // V2: link to agents table
	SecretHash string
	Label      string
	ExpiresAt  *time.Time
}

type NewNodeParams struct {
	Name     string
	Metadata string
}

// NewAgentParams are the fields supplied at enrollment time.
type NewAgentParams struct {
	Name string
}

// ChunkAppendResult is returned to agents so they can short-circuit flushing
// when the server output cap has been hit.
type ChunkAppendResult struct {
	Truncated bool
}

// Store is the full control-plane persistence surface.
type Store interface {
	// tokens
	CreateToken(ctx context.Context, p NewTokenParams) (Token, error)
	GetTokenByID(ctx context.Context, id string) (Token, error)
	ListTokens(ctx context.Context) ([]Token, error)
	RevokeToken(ctx context.Context, id string, at time.Time) error
	MarkJoinTokenUsed(ctx context.Context, id string, at time.Time) error

	// nodes (V1; removed in S11)
	CreateNode(ctx context.Context, p NewNodeParams) (Node, error)
	GetNode(ctx context.Context, id string) (Node, error)
	GetNodeByName(ctx context.Context, name string) (Node, error)
	ListNodes(ctx context.Context) ([]Node, error)
	UpdateNodeHeartbeat(ctx context.Context, id, metadata string, at time.Time) error
	RevokeNode(ctx context.Context, id string, at time.Time) error // status=revoked, rename, revoke agent token

	// agents (V2)
	CreateAgent(ctx context.Context, p NewAgentParams) (Agent, error)
	GetAgent(ctx context.Context, id string) (Agent, error)
	GetAgentByName(ctx context.Context, name string) (Agent, error)
	UpdateAgentHeartbeat(ctx context.Context, id, agentVersion string, at time.Time) error
	UpsertAgentPolicyState(ctx context.Context, p UpsertAgentPolicyStateParams) error
	GetAgentPolicyState(ctx context.Context, agentID string) (AgentPolicyState, error)

	// tasks
	CreateTask(ctx context.Context, nodeID, command, createdBy string, at time.Time) (Task, error)
	GetTask(ctx context.Context, id string) (Task, error)
	ListTasks(ctx context.Context, nodeID string, status TaskStatus, limit int) ([]Task, error)
	ClaimNextPending(ctx context.Context, nodeID string, at time.Time) (*Task, error)
	CompleteTask(ctx context.Context, id string, exitCode int, at time.Time) error
	MarkTaskCancelling(ctx context.Context, id string) error
	MarkTaskCancelled(ctx context.Context, id string, at time.Time) error
	MarkTaskFailedLost(ctx context.Context, id string, at time.Time) error
	PendingCancelsForNode(ctx context.Context, nodeID string) ([]string, error)
	FindStaleRunning(ctx context.Context, olderThan time.Time) ([]Task, error)

	// chunks
	AppendChunk(ctx context.Context, taskID, stream string, data []byte, at time.Time, maxBytes int64) (ChunkAppendResult, error)
	ListChunks(ctx context.Context, taskID, stream string, sinceSeq int64, limit int) ([]Chunk, error)

	// lifecycle
	Close() error
}
