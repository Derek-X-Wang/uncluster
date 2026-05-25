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
	ErrAgentNameTaken = errors.New("store: agent name already in use")
	ErrTokenUsed      = errors.New("store: token already used")
	ErrTokenExpired   = errors.New("store: token expired")
	ErrTokenRevoked   = errors.New("store: token revoked")
)

// AgentStatus is the lifecycle state of a V2 agent.
type AgentStatus string

const (
	AgentOnline  AgentStatus = "online"
	AgentOffline AgentStatus = "offline"
	AgentRevoked AgentStatus = "revoked"
)

type TokenKind string

const (
	TokenJoin   TokenKind = "join"
	TokenAgent  TokenKind = "agent"
	TokenCaller TokenKind = "caller" // V2 — Caller token (operator CLI)
)

// Agent is the V2 enrollment record. Created when an Agent registers via
// POST /v1/agent/register; linked to its agent token via the tokens table.
type Agent struct {
	ID               string
	Name             string
	CreatedAt        time.Time
	LastSeenAt       *time.Time
	Status           AgentStatus
	AgentVersion     string
	FailClosedAfter  *int64 // seconds; nil means "no fail-closed"
}

// AgentEndpoint is one subnet→address binding for an agent.
type AgentEndpoint struct {
	Subnet  string
	Address string
}

// ACLEntry is a single access-control grant: caller_token_id may SSH to
// agent_id as username. The UNIQUE constraint is (caller_token_id, agent_id, username).
type ACLEntry struct {
	ID            string
	CallerTokenID string
	AgentID       string
	Username      string
	CreatedAt     time.Time
	CreatedBy     *string
}

// CreateACLParams holds the fields needed to create an ACL entry.
type CreateACLParams struct {
	CallerTokenID string
	AgentID       string
	Username      string
	CreatedBy     *string
}

// ListACLFilter controls which rows are returned by ListACL. Zero values mean
// "no filter for this field".
type ListACLFilter struct {
	CallerTokenID string // filter by caller, or ""
	AgentID       string // filter by agent, or ""
}

// PolicyPrincipal is one user and the set of caller_token_ids permitted to
// SSH as that user on a given agent.
type PolicyPrincipal struct {
	Username      string
	CallerTokenIDs []string
}

// PolicySnapshot is the server-side projection of ACL rows for one agent.
// Version is monotonically incremented (stored in agent_policy_versions).
// Hash is blake3:<hex> over the canonical serialisation of Principals.
type PolicySnapshot struct {
	AgentID    string
	Version    int64
	Hash       string // "blake3:<hex>" or "" when ACL is empty
	Principals []PolicyPrincipal
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
	AgentID    *string // set for agent tokens (V2)
	SecretHash string
	Label      string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	UsedAt     *time.Time
	RevokedAt  *time.Time
}

type NewTokenParams struct {
	ID         string // if empty, the store generates one
	Kind       TokenKind
	AgentID    *string  // V2: link to agents table
	SecretHash string
	Label      string
	ExpiresAt  *time.Time
}

// NewAgentParams are the fields supplied at enrollment time.
type NewAgentParams struct {
	Name string
}

// CertEvent is one row in cert_issuance_events.
type CertEvent struct {
	RequestID     string
	TS            time.Time
	CallerTokenID string
	TargetAgentID string // "" if agent could not be resolved
	Username      string
	CertPrincipal string  // the caller_token_id used as the SSH principal; "" on denial
	PubkeyFP      string  // pubkey fingerprint; "" on denial
	TTLSeconds    int
	Serial        uint64  // 0 on denial
	KeyID         string  // "" on denial
	Outcome       string  // "signed" or "denied"
	DenialReason  string  // "" on success
}

// CertEventFilter controls which rows are returned by ListCertEvents.
type CertEventFilter struct {
	CallerTokenID string   // "" = any
	AgentID       string   // "" = any
	Username      string   // "" = any
	Outcome       string   // "" = any; "signed" | "denied"
	Since         *time.Time
	Limit         int // 0 = default (100)
}

// UpdatePolicy is the server-side update configuration (single row in DB).
// ExpectedVersion is empty when no update is mandated.
type UpdatePolicy struct {
	ExpectedVersion    string
	AssetURLTemplate   string
	SHA256URLTemplate  string
	Force              bool
	UpdatedAt          time.Time
}

// SetUpdatePolicyParams holds fields for upserting the update policy.
type SetUpdatePolicyParams struct {
	ExpectedVersion   string
	AssetURLTemplate  string
	SHA256URLTemplate string
	Force             bool
}

// Store is the full control-plane persistence surface.
type Store interface {
	// tokens
	CreateToken(ctx context.Context, p NewTokenParams) (Token, error)
	GetTokenByID(ctx context.Context, id string) (Token, error)
	ListTokens(ctx context.Context) ([]Token, error)
	RevokeToken(ctx context.Context, id string, at time.Time) error
	MarkJoinTokenUsed(ctx context.Context, id string, at time.Time) error

	// agents (V2)
	CreateAgent(ctx context.Context, p NewAgentParams) (Agent, error)
	GetAgent(ctx context.Context, id string) (Agent, error)
	GetAgentByName(ctx context.Context, name string) (Agent, error)
	ListAgents(ctx context.Context) ([]Agent, error)
	UpdateAgentHeartbeat(ctx context.Context, id, agentVersion string, at time.Time) error
	RevokeAgent(ctx context.Context, id string, at time.Time) error
	SetAgentFailClosedAfter(ctx context.Context, id string, seconds *int64) error
	UpsertAgentPolicyState(ctx context.Context, p UpsertAgentPolicyStateParams) error
	GetAgentPolicyState(ctx context.Context, agentID string) (AgentPolicyState, error)

	// acl (V2)
	CreateACL(ctx context.Context, p CreateACLParams) (ACLEntry, error)
	GetACL(ctx context.Context, id string) (ACLEntry, error)
	DeleteACL(ctx context.Context, id string) error
	ListACL(ctx context.Context, f ListACLFilter) ([]ACLEntry, error)
	GetPolicySnapshot(ctx context.Context, agentID string) (PolicySnapshot, error)

	// agent endpoints (V2)
	UpsertAgentEndpoints(ctx context.Context, agentID string, endpoints []AgentEndpoint) error
	ListAgentEndpoints(ctx context.Context, agentID string) ([]AgentEndpoint, error)

	// cert events (V2 — S6)
	WriteCertEvent(ctx context.Context, e CertEvent) error
	ListCertEvents(ctx context.Context, f CertEventFilter) ([]CertEvent, error)

	// update policy (S8b)
	GetUpdatePolicy(ctx context.Context) (UpdatePolicy, error)
	SetUpdatePolicy(ctx context.Context, p SetUpdatePolicyParams) error

	// lifecycle
	Close() error
}
