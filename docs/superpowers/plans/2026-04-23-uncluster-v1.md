# Uncluster V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working V1 of Uncluster — operator can register nodes, list them with live metrics, run shell commands on any node with live-streamed output, cancel tasks, and revoke nodes.

**Architecture:** Single Go binary `uncluster` with three roles (server / agent / client) selected by subcommand. Nodes dial out over HTTPS with 30s long-poll for task pickup; all state in SQLite on the control plane; CLI tails live output via SSE. OpenAPI YAML is the REST contract of record.

**Tech Stack:** Go 1.22+, `net/http` + `chi` router, `modernc.org/sqlite` (pure Go), `spf13/cobra` CLI, `BurntSushi/toml` config, `shirou/gopsutil/v3` metrics, `kardianos/service` for launchd/systemd install, `google/uuid`, `x/crypto/argon2`.

**Reference:** [`docs/superpowers/specs/2026-04-23-uncluster-v1-design.md`](../specs/2026-04-23-uncluster-v1-design.md)

---

## Ship points

Incremental checkpoints where a coherent piece is demoable/shippable:

- **SP1 — after Phase 3:** Server binary runs, serves `/healthz`, CLI mints tokens and lists them.
- **SP2 — after Phase 6:** Agent joins, heartbeats, appears in `uncluster nodes ls` with live metrics.
- **SP3 — after Phase 9:** `uncluster run <node> -- <cmd>` works end-to-end with live-streamed stdout/stderr. **MVP ships here if needed.**
- **SP4 — after Phase 12:** Cancellation + revoke + reaper + output cap all working. Acceptance criteria §11 #7–#10 pass.
- **SP5 — after Phase 14:** Cross-compile tarballs, CI green, OpenAPI drift test passing. V1 complete.

---

## File structure (end state)

```
uncluster/
├── api/
│   └── openapi.yaml
├── cmd/
│   └── uncluster/
│       └── main.go                   # cobra root; dispatches to internal/cli
├── internal/
│   ├── api/
│   │   └── types.go                  # hand-written request/response structs (codegen optional per §11 #13)
│   ├── agent/
│   │   ├── agent.go                  # Run(): wires heartbeat + poll + cancel loops
│   │   ├── config.go                 # ~/.config/uncluster/agent.toml read/write
│   │   ├── execute.go                # exec.Command + stdout/stderr streaming
│   │   ├── cancel.go                 # cancelDispatcher: map[taskID]CancelFunc
│   │   ├── metrics.go                # gopsutil heartbeat payload
│   │   └── http.go                   # server client (register, heartbeat, next-task, chunks, complete)
│   ├── cli/
│   │   ├── root.go                   # cobra root
│   │   ├── agent_cmd.go              # uncluster agent {join,run,install,uninstall}
│   │   ├── config_cmd.go             # uncluster config {set,show}
│   │   ├── nodes_cmd.go              # uncluster nodes {ls,show,rm}
│   │   ├── run_cmd.go                # uncluster run <node> -- <cmd>
│   │   ├── server_cmd.go             # uncluster server {start,token}
│   │   ├── tasks_cmd.go              # uncluster tasks {ls,show,tail,cancel}
│   │   ├── tokenio.go                # --token-stdin / UNCLUSTER_TOKEN helpers
│   │   └── httpclient.go             # HTTP client wrapper used by client-side commands
│   ├── server/
│   │   ├── server.go                 # New(), Start()
│   │   ├── router.go                 # chi routes
│   │   ├── middleware.go             # auth, logging, recovery, request id
│   │   ├── handlers_agent.go         # /v1/agent/* handlers
│   │   ├── handlers_cli.go           # /v1/{nodes,tasks,tokens} handlers
│   │   ├── handlers_health.go        # /healthz
│   │   ├── dispatcher.go             # Dispatcher interface + in-process impl
│   │   ├── sse.go                    # SSE helper
│   │   └── reaper.go                 # 60s no-heartbeat task reaper
│   ├── store/
│   │   ├── store.go                  # Store interface
│   │   ├── sqlite.go                 # SQLite impl
│   │   └── migrations.go             # schema DDL slice + schema_version table
│   ├── token/
│   │   └── token.go                  # Generate, Parse, HashSecret, VerifySecret
│   └── version/
│       └── version.go                # Version string set via -ldflags
├── scripts/
│   ├── build.sh                      # cross-compile matrix
│   └── generate.sh                   # optional oapi-codegen driver
├── .github/
│   └── workflows/
│       └── ci.yml                    # build/test/lint on linux+darwin, amd64+arm64
├── docs/
│   └── superpowers/
│       ├── plans/
│       │   └── 2026-04-23-uncluster-v1.md
│       └── specs/
│           └── 2026-04-23-uncluster-v1-design.md
├── go.mod
├── go.sum
├── Makefile
└── .gitignore
```

---

## Conventions used throughout this plan

- **Every task ends in a commit.** Squash only if the final commit message covers the whole task.
- **Tests first.** Where a task has multiple related tests, they may be written as one step (to avoid 20-step churn) but the "run-to-verify-fail" step still precedes implementation.
- **All SQL is prepared statements** via `database/sql` with `?` placeholders.
- **All time is `time.Now().Unix()` (seconds)** unless otherwise noted; the `INTEGER` columns in the schema expect unix seconds.
- **Error style:** `fmt.Errorf("verb noun: %w", err)` — wrap, don't stringify.
- **Logging:** `log/slog` with JSON handler when `UNCLUSTER_LOG=json`, text handler otherwise.
- **No global state.** `store.Store`, `server.Server`, `agent.Agent` are struct types; everything is passed explicitly.
- **go.sum must be in commits.** Run `go mod tidy` before committing whenever deps change.

---

## Phase 0: Project scaffolding

### Task 0.1: Initialize Go module and commit baseline

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `Makefile`

- [ ] **Step 1: Create `go.mod`**

Run:
```bash
go mod init github.com/derek-x-wang/uncluster
```

Expected: `go.mod` created with module path and `go 1.22` directive. (Adjust if `go version` reports a different minor; 1.22 minimum.)

- [ ] **Step 2: Create `.gitignore`**

Write `/Users/derekxwang/Development/incubator/Uncluster/uncluster/.gitignore`:

```
# binaries
/uncluster
/dist/
*.exe

# Go
vendor/
*.test
coverage.out
coverage.html

# editor / OS
.DS_Store
.vscode/
.idea/

# local state
*.db
*.db-journal
*.db-wal
*.db-shm
/.local/
```

- [ ] **Step 3: Create `Makefile`**

Write `/Users/derekxwang/Development/incubator/Uncluster/uncluster/Makefile`:

```makefile
.PHONY: build test lint tidy clean

VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS := -s -w -X github.com/derek-x-wang/uncluster/internal/version.Version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o uncluster ./cmd/uncluster

test:
	go test ./... -race -count=1

lint:
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed; skipping"; fi

tidy:
	go mod tidy

clean:
	rm -rf ./uncluster ./dist ./coverage.out
```

- [ ] **Step 4: Commit**

```bash
git add go.mod .gitignore Makefile
git commit -m "chore: bootstrap go module, gitignore, makefile"
```

---

### Task 0.2: Add core third-party dependencies

**Files:**
- Modify: `go.mod`, `go.sum` (via `go get`)

- [ ] **Step 1: Install dependencies**

Run:
```bash
go get github.com/go-chi/chi/v5@latest
go get github.com/spf13/cobra@latest
go get github.com/BurntSushi/toml@latest
go get modernc.org/sqlite@latest
go get github.com/google/uuid@latest
go get golang.org/x/crypto/argon2
go get github.com/shirou/gopsutil/v3/...@latest
go get github.com/kardianos/service@latest
go mod tidy
```

Expected: `go.mod` lists all of the above; `go.sum` populated; no errors.

- [ ] **Step 2: Verify compilation**

Run:
```bash
go build ./...
```

Expected: exits 0 (no packages yet to compile, but `go build ./...` with nothing under `./cmd` or `./internal` is a no-op success; if it errors on "no Go files", that's fine for now).

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add core dependencies (chi, cobra, toml, sqlite, uuid, argon2, gopsutil, kardianos/service)"
```

---

### Task 0.3: Create version package and CLI entrypoint stub

**Files:**
- Create: `internal/version/version.go`
- Create: `cmd/uncluster/main.go`
- Create: `internal/cli/root.go`

- [ ] **Step 1: Write `internal/version/version.go`**

```go
package version

// Version is set at build time via -ldflags.
var Version = "dev"
```

- [ ] **Step 2: Write `internal/cli/root.go`**

```go
package cli

import (
	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/version"
)

// NewRoot returns the root cobra command.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "uncluster",
		Short:         "Uncluster — a lightweight personal compute layer",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// Subcommands are attached in later phases.
	return root
}
```

- [ ] **Step 3: Write `cmd/uncluster/main.go`**

```go
package main

import (
	"fmt"
	"os"

	"github.com/derek-x-wang/uncluster/internal/cli"
)

func main() {
	if err := cli.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Build and smoke test**

Run:
```bash
make build
./uncluster --version
```

Expected: binary builds; `--version` prints `uncluster version dev` (or similar cobra-default output).

- [ ] **Step 5: Commit**

```bash
git add cmd/uncluster internal/version internal/cli
git commit -m "feat: cli entrypoint skeleton with cobra root command"
```

---

### Task 0.4: Create empty OpenAPI contract file

**Files:**
- Create: `api/openapi.yaml`

- [ ] **Step 1: Write `api/openapi.yaml`**

```yaml
openapi: 3.1.0
info:
  title: Uncluster Control Plane API
  version: 0.1.0
  description: |
    Wire protocol between the `uncluster` CLI, agents, and the control plane.
    This file is the source of truth; see
    docs/superpowers/specs/2026-04-23-uncluster-v1-design.md for design.
servers:
  - url: https://uncluster.example.com:7777
    description: Example production URL (operator-provided)

paths:
  /healthz:
    get:
      summary: Liveness probe
      security: []
      responses:
        "200":
          description: OK
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok: { type: boolean }
                  version: { type: string }

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: uct_<kind>_<id>_<secret>

  schemas: {}

security:
  - bearerAuth: []
```

Further paths are added in later phases as their handlers land.

- [ ] **Step 2: Commit**

```bash
git add api/openapi.yaml
git commit -m "docs: openapi.yaml skeleton — healthz and bearer auth scheme only"
```

---

## Phase 1: Token module

### Task 1.1: Token generation, parsing, hashing, and verification

**Files:**
- Create: `internal/token/token.go`
- Create: `internal/token/token_test.go`

- [ ] **Step 1: Write `internal/token/token_test.go`**

```go
package token_test

import (
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/token"
)

func TestGenerateAndParseRoundTrip(t *testing.T) {
	for _, kind := range []token.Kind{token.KindJoin, token.KindAgent, token.KindCLI} {
		tok, err := token.Generate(kind)
		if err != nil {
			t.Fatalf("Generate(%s): %v", kind, err)
		}
		if !strings.HasPrefix(tok.String(), "uct_"+string(kind)+"_") {
			t.Fatalf("prefix mismatch: %s", tok.String())
		}
		parsed, err := token.Parse(tok.String())
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if parsed.Kind != kind {
			t.Errorf("kind: got %s want %s", parsed.Kind, kind)
		}
		if parsed.ID != tok.ID {
			t.Errorf("id: got %s want %s", parsed.ID, tok.ID)
		}
		if parsed.Secret != tok.Secret {
			t.Errorf("secret: got %s want %s", parsed.Secret, tok.Secret)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"uct_cli_",
		"uct_cli_abc",
		"uct_cli_abc_",
		"uct_xyz_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"not_a_token_at_all",
	}
	for _, c := range cases {
		if _, err := token.Parse(c); err == nil {
			t.Errorf("Parse(%q) should have failed", c)
		}
	}
}

func TestHashAndVerify(t *testing.T) {
	tok, err := token.Generate(token.KindAgent)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := token.HashSecret(tok.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if hash == tok.Secret {
		t.Fatal("hash must not equal plaintext secret")
	}
	ok, err := token.VerifySecret(tok.Secret, hash)
	if err != nil || !ok {
		t.Fatalf("VerifySecret(correct): ok=%v err=%v", ok, err)
	}
	ok, err = token.VerifySecret("wrong-secret", hash)
	if err != nil {
		t.Fatalf("VerifySecret(wrong) err: %v", err)
	}
	if ok {
		t.Fatal("VerifySecret(wrong) returned true")
	}
}

func TestIDLength(t *testing.T) {
	tok, err := token.Generate(token.KindCLI)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.ID) != 16 {
		t.Fatalf("ID length: got %d want 16 (%q)", len(tok.ID), tok.ID)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./internal/token/...
```

Expected: FAIL with "undefined: token.Generate" etc.

- [ ] **Step 3: Write `internal/token/token.go`**

```go
// Package token defines Uncluster's token format and verification primitives.
//
// Token string: uct_<kind>_<id>_<secret>
//   - kind:   "join" | "agent" | "cli"
//   - id:     16 base32 chars (80 bits). Public lookup key.
//   - secret: 52 base32 chars (~256 bits). Only argon2id(secret) is stored.
package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Kind string

const (
	KindJoin  Kind = "join"
	KindAgent Kind = "agent"
	KindCLI   Kind = "cli"

	idLen     = 16 // base32 chars
	secretLen = 52 // base32 chars
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type Token struct {
	Kind   Kind
	ID     string
	Secret string
}

func (t Token) String() string {
	return fmt.Sprintf("uct_%s_%s_%s", t.Kind, t.ID, t.Secret)
}

// Generate produces a fresh token of the given kind.
func Generate(kind Kind) (Token, error) {
	if !validKind(kind) {
		return Token{}, fmt.Errorf("invalid kind %q", kind)
	}
	id, err := randBase32(10) // 10 bytes → 16 base32 chars
	if err != nil {
		return Token{}, fmt.Errorf("generate id: %w", err)
	}
	sec, err := randBase32(32) // 32 bytes → 52 base32 chars (56 then trimmed? see below)
	if err != nil {
		return Token{}, fmt.Errorf("generate secret: %w", err)
	}
	// 32 raw bytes base32-no-padding = 52 chars exactly.
	return Token{Kind: kind, ID: id, Secret: sec}, nil
}

// Parse extracts the three components. Rejects malformed strings.
func Parse(s string) (Token, error) {
	const prefix = "uct_"
	if !strings.HasPrefix(s, prefix) {
		return Token{}, errors.New("token: missing uct_ prefix")
	}
	rest := s[len(prefix):]
	parts := strings.SplitN(rest, "_", 3)
	if len(parts) != 3 {
		return Token{}, errors.New("token: wrong segment count")
	}
	kind := Kind(parts[0])
	if !validKind(kind) {
		return Token{}, fmt.Errorf("token: unknown kind %q", kind)
	}
	if len(parts[1]) != idLen {
		return Token{}, fmt.Errorf("token: id length %d want %d", len(parts[1]), idLen)
	}
	if len(parts[2]) != secretLen {
		return Token{}, fmt.Errorf("token: secret length %d want %d", len(parts[2]), secretLen)
	}
	return Token{Kind: kind, ID: parts[1], Secret: parts[2]}, nil
}

// HashSecret produces an argon2id hash string of a token secret, suitable for DB storage.
func HashSecret(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("hash salt: %w", err)
	}
	// Parameters: time=3, memory=64 MiB, parallelism=2, 32-byte key.
	const timeCost, memoryCost, parallelism, keyLen = 3, 64 * 1024, 2, 32
	key := argon2.IDKey([]byte(secret), salt, timeCost, memoryCost, parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memoryCost, timeCost, parallelism,
		b32.EncodeToString(salt), b32.EncodeToString(key)), nil
}

// VerifySecret compares a plaintext secret against a stored argon2id hash.
func VerifySecret(secret, stored string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("verify: malformed hash")
	}
	var m, t, p int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, fmt.Errorf("verify params: %w", err)
	}
	salt, err := b32.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("verify salt: %w", err)
	}
	want, err := b32.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("verify key: %w", err)
	}
	got := argon2.IDKey([]byte(secret), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func randBase32(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

func validKind(k Kind) bool {
	switch k {
	case KindJoin, KindAgent, KindCLI:
		return true
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./internal/token/... -race -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/token
git commit -m "feat(token): generate/parse/hash/verify with uct_<kind>_<id>_<secret> format

Public ID (16 base32 chars) is the lookup key; only the 52-char secret is
argon2id-hashed. This makes auth O(1) indexed lookup + one hash compare
per request — see spec §6.6 for the DoS rationale."
```

---

## Phase 2: Store (SQLite)

### Task 2.1: Store interface

**Files:**
- Create: `internal/store/store.go`

- [ ] **Step 1: Write `internal/store/store.go`**

```go
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
	ErrNotFound      = errors.New("store: not found")
	ErrNameTaken     = errors.New("store: node name already in use")
	ErrTokenUsed     = errors.New("store: token already used")
	ErrTokenExpired  = errors.New("store: token expired")
	ErrTokenRevoked  = errors.New("store: token revoked")
	ErrNotClaimable  = errors.New("store: task is not claimable")
	ErrTaskCompleted = errors.New("store: task already completed")
)

type NodeStatus string

const (
	NodeOnline   NodeStatus = "online"
	NodeOffline  NodeStatus = "offline"
	NodeRevoked  NodeStatus = "revoked"
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
	TokenJoin  TokenKind = "join"
	TokenAgent TokenKind = "agent"
	TokenCLI   TokenKind = "cli"
)

type Node struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	LastSeenAt *time.Time
	Status     NodeStatus
	Metadata   string // JSON blob (free-form)
}

type Token struct {
	ID          string
	Kind        TokenKind
	NodeID      *string
	SecretHash  string
	Label       string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	UsedAt      *time.Time
	RevokedAt   *time.Time
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
	Kind       TokenKind
	NodeID     *string
	SecretHash string
	Label      string
	ExpiresAt  *time.Time
}

type NewNodeParams struct {
	Name     string
	Metadata string
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

	// nodes
	CreateNode(ctx context.Context, p NewNodeParams) (Node, error)
	GetNode(ctx context.Context, id string) (Node, error)
	GetNodeByName(ctx context.Context, name string) (Node, error)
	ListNodes(ctx context.Context) ([]Node, error)
	UpdateNodeHeartbeat(ctx context.Context, id, metadata string, at time.Time) error
	RevokeNode(ctx context.Context, id string, at time.Time) error // status=revoked, rename, revoke agent token

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
```

- [ ] **Step 2: Verify compilation**

Run:
```bash
go build ./internal/store/...
```

Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add internal/store/store.go
git commit -m "feat(store): interface covering tokens, nodes, tasks, chunks

All concrete impls satisfy this; SQLite first, future Postgres/DynamoDB
variants plug in behind it without touching handlers."
```

---

### Task 2.2: SQLite migrations

**Files:**
- Create: `internal/store/migrations.go`

- [ ] **Step 1: Write `internal/store/migrations.go`**

```go
package store

// migrations is an append-only slice of DDL statements. Each index is the
// target schema_version after that statement runs. The SQLite store runs any
// statement whose index is > current schema_version, in order, inside a tx.
var migrations = []string{
	// 0: sentinel (no-op so indices line up with schema_version)
	`SELECT 1`,

	// 1: initial schema
	`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY
	)`,

	// 2: nodes
	`CREATE TABLE nodes (
		id            TEXT PRIMARY KEY,
		name          TEXT NOT NULL UNIQUE,
		created_at    INTEGER NOT NULL,
		last_seen_at  INTEGER,
		status        TEXT NOT NULL,
		metadata_json TEXT NOT NULL DEFAULT '{}'
	)`,

	// 3: tokens
	`CREATE TABLE tokens (
		id          TEXT PRIMARY KEY,
		kind        TEXT NOT NULL,
		node_id     TEXT REFERENCES nodes(id),
		secret_hash TEXT NOT NULL,
		label       TEXT NOT NULL DEFAULT '',
		created_at  INTEGER NOT NULL,
		expires_at  INTEGER,
		used_at     INTEGER,
		revoked_at  INTEGER
	)`,
	`CREATE INDEX idx_tokens_node ON tokens(node_id)`,

	// 4: tasks
	`CREATE TABLE tasks (
		id               TEXT PRIMARY KEY,
		node_id          TEXT NOT NULL REFERENCES nodes(id),
		command          TEXT NOT NULL,
		status           TEXT NOT NULL,
		exit_code        INTEGER,
		created_at       INTEGER NOT NULL,
		started_at       INTEGER,
		finished_at      INTEGER,
		output_bytes     INTEGER NOT NULL DEFAULT 0,
		output_truncated INTEGER NOT NULL DEFAULT 0,
		created_by       TEXT
	)`,
	`CREATE INDEX idx_tasks_node_status ON tasks(node_id, status)`,
	`CREATE INDEX idx_tasks_created ON tasks(created_at DESC)`,

	// 5: chunks
	`CREATE TABLE task_chunks (
		task_id    TEXT NOT NULL REFERENCES tasks(id),
		stream     TEXT NOT NULL,
		seq        INTEGER NOT NULL,
		data       BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (task_id, stream, seq)
	)`,
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/store/migrations.go
git commit -m "feat(store): sqlite migrations — nodes, tokens, tasks, task_chunks

Chunk PK is (task_id, stream, seq) so stdout and stderr sequence
independently (spec §4, codex-driven fix from review pass)."
```

---

### Task 2.3: SQLite implementation — open, migrate, token ops

**Files:**
- Create: `internal/store/sqlite.go`
- Create: `internal/store/sqlite_test.go`

- [ ] **Step 1: Write `internal/store/sqlite_test.go`**

```go
package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/store"
)

func newStore(t *testing.T) store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateAndGetToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	tok, err := s.CreateToken(ctx, store.NewTokenParams{
		Kind:       store.TokenCLI,
		SecretHash: "$argon2id$...",
		Label:      "my-laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTokenByID(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != store.TokenCLI || got.Label != "my-laptop" {
		t.Fatalf("unexpected token: %+v", got)
	}
}

func TestRevokeToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenCLI, SecretHash: "h"})
	if err := s.RevokeToken(ctx, tok.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTokenByID(ctx, tok.ID)
	if got.RevokedAt == nil {
		t.Fatal("expected RevokedAt to be set")
	}
}

func TestMarkJoinTokenUsed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tok, _ := s.CreateToken(ctx, store.NewTokenParams{Kind: store.TokenJoin, SecretHash: "h"})
	if err := s.MarkJoinTokenUsed(ctx, tok.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTokenByID(ctx, tok.ID)
	if got.UsedAt == nil {
		t.Fatal("expected UsedAt to be set")
	}
	// Using twice should fail.
	if err := s.MarkJoinTokenUsed(ctx, tok.ID, time.Now()); err == nil {
		t.Fatal("expected ErrTokenUsed on second use")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
go test ./internal/store/... -race -v
```

Expected: FAIL with "undefined: store.OpenSQLite".

- [ ] **Step 3: Write `internal/store/sqlite.go` (initial: open + migrate + token ops)**

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type sqliteStore struct {
	db *sql.DB
}

// OpenSQLite opens (or creates) the SQLite DB at path and applies migrations.
func OpenSQLite(path string) (Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Limit to one writer; readers scale via WAL. Simpler and avoids lock surprises for V1.
	db.SetMaxOpenConns(1)
	s := &sqliteStore{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

func (s *sqliteStore) migrate() error {
	// Ensure schema_version row exists.
	if _, err := s.db.Exec(migrations[1]); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO schema_version(version) VALUES (0)`); err != nil {
		return fmt.Errorf("seed schema_version: %w", err)
	}
	var current int
	if err := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`).Scan(&current); err != nil {
		return fmt.Errorf("read schema_version: %w", err)
	}
	for i := current + 1; i < len(migrations); i++ {
		if i <= 1 { // sentinel / schema_version already handled
			continue
		}
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", i, err)
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", i, err)
		}
		if _, err := tx.Exec(`UPDATE schema_version SET version = ?`, i); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("bump schema_version to %d: %w", i, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", i, err)
		}
	}
	return nil
}

// ------------- tokens -------------

func (s *sqliteStore) CreateToken(ctx context.Context, p NewTokenParams) (Token, error) {
	id := shortID(16)
	now := time.Now()
	var expiresAt *int64
	if p.ExpiresAt != nil {
		v := p.ExpiresAt.Unix()
		expiresAt = &v
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens(id, kind, node_id, secret_hash, label, created_at, expires_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		id, string(p.Kind), p.NodeID, p.SecretHash, p.Label, now.Unix(), expiresAt)
	if err != nil {
		return Token{}, fmt.Errorf("insert token: %w", err)
	}
	return s.GetTokenByID(ctx, id)
}

func (s *sqliteStore) GetTokenByID(ctx context.Context, id string) (Token, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, kind, node_id, secret_hash, label, created_at, expires_at, used_at, revoked_at
		 FROM tokens WHERE id = ?`, id)
	return scanToken(row)
}

func (s *sqliteStore) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, node_id, secret_hash, label, created_at, expires_at, used_at, revoked_at
		 FROM tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *sqliteStore) RevokeToken(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		at.Unix(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) MarkJoinTokenUsed(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET used_at = ?
		 WHERE id = ? AND kind = 'join' AND used_at IS NULL AND revoked_at IS NULL`,
		at.Unix(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Either the token doesn't exist, is not a join token, or was already used/revoked.
		t, gerr := s.GetTokenByID(ctx, id)
		if gerr != nil {
			return ErrNotFound
		}
		if t.UsedAt != nil {
			return ErrTokenUsed
		}
		if t.RevokedAt != nil {
			return ErrTokenRevoked
		}
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanToken(r rowScanner) (Token, error) {
	var (
		t                                    Token
		nodeID                               sql.NullString
		label                                sql.NullString
		expiresAt, usedAt, revokedAt         sql.NullInt64
		createdAt                            int64
	)
	if err := r.Scan(&t.ID, &t.Kind, &nodeID, &t.SecretHash, &label, &createdAt, &expiresAt, &usedAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Token{}, ErrNotFound
		}
		return Token{}, err
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	if nodeID.Valid {
		v := nodeID.String
		t.NodeID = &v
	}
	if label.Valid {
		t.Label = label.String
	}
	if expiresAt.Valid {
		v := time.Unix(expiresAt.Int64, 0)
		t.ExpiresAt = &v
	}
	if usedAt.Valid {
		v := time.Unix(usedAt.Int64, 0)
		t.UsedAt = &v
	}
	if revokedAt.Valid {
		v := time.Unix(revokedAt.Int64, 0)
		t.RevokedAt = &v
	}
	return t, nil
}

func shortID(nchar int) string {
	// UUID v4 → 32 hex chars → take first nchar as a short base16 identifier.
	u := uuid.New().String()
	u = u[:8] + u[9:13] + u[14:18] + u[19:23] + u[24:]
	if nchar > len(u) {
		nchar = len(u)
	}
	return u[:nchar]
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./internal/store/... -race -v
```

Expected: all three tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/sqlite.go internal/store/sqlite_test.go
git commit -m "feat(store): sqlite open + migrations + token CRUD

WAL mode, busy_timeout=5s, foreign_keys ON, single writer.
Migrations are idempotent via schema_version."
```

---

### Task 2.4: SQLite node operations + revoke-with-rename

**Files:**
- Modify: `internal/store/sqlite.go`
- Modify: `internal/store/sqlite_test.go`

- [ ] **Step 1: Add tests to `internal/store/sqlite_test.go`**

Append:

```go
func TestCreateAndListNodes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, err := s.CreateNode(ctx, store.NewNodeParams{Name: "old-macbook", Metadata: `{"os":"darwin"}`})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNodeByName(ctx, "old-macbook")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != n.ID || got.Status != store.NodeOnline {
		t.Fatalf("unexpected node: %+v", got)
	}
	list, _ := s.ListNodes(ctx)
	if len(list) != 1 {
		t.Fatalf("ListNodes len: got %d want 1", len(list))
	}
}

func TestCreateNodeRejectsDuplicateName(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.CreateNode(ctx, store.NewNodeParams{Name: "dup"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateNode(ctx, store.NewNodeParams{Name: "dup"})
	if err == nil || !errors.Is(err, store.ErrNameTaken) {
		t.Fatalf("expected ErrNameTaken, got: %v", err)
	}
}

func TestRevokeNodeRenamesAndFreesName(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "laptop"})
	// Create an agent token for this node.
	_, _ = s.CreateToken(ctx, store.NewTokenParams{
		Kind: store.TokenAgent, NodeID: &n.ID, SecretHash: "h",
	})
	if err := s.RevokeNode(ctx, n.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	revoked, _ := s.GetNode(ctx, n.ID)
	if revoked.Status != store.NodeRevoked {
		t.Fatal("status not revoked")
	}
	if revoked.Name == "laptop" {
		t.Fatalf("name should have been renamed, got: %q", revoked.Name)
	}
	// Same name must be available for a fresh node.
	if _, err := s.CreateNode(ctx, store.NewNodeParams{Name: "laptop"}); err != nil {
		t.Fatalf("name should be free: %v", err)
	}
}
```

And add at the top of the file:
```go
import "errors"
```
(if not already present in the imports block)

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./internal/store/... -race -v
```

Expected: three new tests FAIL with undefined methods.

- [ ] **Step 3: Append node operations to `internal/store/sqlite.go`**

Append:

```go
// ------------- nodes -------------

func (s *sqliteStore) CreateNode(ctx context.Context, p NewNodeParams) (Node, error) {
	id := "node_" + shortID(24)
	now := time.Now()
	meta := p.Metadata
	if meta == "" {
		meta = "{}"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO nodes(id, name, created_at, status, metadata_json)
		 VALUES(?, ?, ?, ?, ?)`,
		id, p.Name, now.Unix(), string(NodeOnline), meta)
	if err != nil {
		if isUniqueViolation(err) {
			return Node{}, ErrNameTaken
		}
		return Node{}, fmt.Errorf("insert node: %w", err)
	}
	return s.GetNode(ctx, id)
}

func (s *sqliteStore) GetNode(ctx context.Context, id string) (Node, error) {
	return s.queryNode(ctx, `WHERE id = ?`, id)
}

func (s *sqliteStore) GetNodeByName(ctx context.Context, name string) (Node, error) {
	return s.queryNode(ctx, `WHERE name = ?`, name)
}

func (s *sqliteStore) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, created_at, last_seen_at, status, metadata_json
		 FROM nodes ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateNodeHeartbeat(ctx context.Context, id, metadata string, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET last_seen_at = ?, metadata_json = ?, status = 'online'
		 WHERE id = ? AND status != 'revoked'`,
		at.Unix(), metadata, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) RevokeNode(ctx context.Context, id string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var currentName string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM nodes WHERE id = ?`, id).Scan(&currentName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	newName := fmt.Sprintf("%s-revoked-%d", currentName, at.Unix())
	if _, err := tx.ExecContext(ctx,
		`UPDATE nodes SET status = 'revoked', name = ? WHERE id = ?`, newName, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE tokens SET revoked_at = ?
		 WHERE node_id = ? AND kind = 'agent' AND revoked_at IS NULL`,
		at.Unix(), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *sqliteStore) queryNode(ctx context.Context, where string, arg any) (Node, error) {
	q := `SELECT id, name, created_at, last_seen_at, status, metadata_json FROM nodes ` + where
	return scanNode(s.db.QueryRowContext(ctx, q, arg))
}

func scanNode(r rowScanner) (Node, error) {
	var (
		n          Node
		lastSeen   sql.NullInt64
		createdAt  int64
	)
	if err := r.Scan(&n.ID, &n.Name, &createdAt, &lastSeen, &n.Status, &n.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Node{}, ErrNotFound
		}
		return Node{}, err
	}
	n.CreatedAt = time.Unix(createdAt, 0)
	if lastSeen.Valid {
		v := time.Unix(lastSeen.Int64, 0)
		n.LastSeenAt = &v
	}
	return n, nil
}

func isUniqueViolation(err error) bool {
	// modernc.org/sqlite returns errors whose message contains "UNIQUE constraint failed".
	return err != nil && containsAny(err.Error(), "UNIQUE constraint failed", "constraint failed: UNIQUE")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./internal/store/... -race -v
```

Expected: all node tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat(store): node CRUD + revoke-with-rename

Revoke sets status=revoked and renames to <name>-revoked-<ts> so the
original name is free to reuse (spec §6.5, codex fix)."
```

---

### Task 2.5: SQLite task operations — create, atomic claim, complete, list, find-stale

**Files:**
- Modify: `internal/store/sqlite.go`
- Modify: `internal/store/sqlite_test.go`

- [ ] **Step 1: Add tests to `internal/store/sqlite_test.go`**

Append:

```go
func TestAtomicClaim_NoDoubleAssignment(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	task, _ := s.CreateTask(ctx, n.ID, "echo hi", "cli", time.Now())

	// Two concurrent claim attempts: exactly one wins.
	type result struct {
		task *store.Task
		err  error
	}
	ch := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			got, err := s.ClaimNextPending(ctx, n.ID, time.Now())
			ch <- result{got, err}
		}()
	}
	var winners int
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.task != nil {
			if r.task.ID != task.ID {
				t.Fatalf("claimed wrong task: %q", r.task.ID)
			}
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", winners)
	}
}

func TestClaimSkipsCancelled(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	task, _ := s.CreateTask(ctx, n.ID, "nope", "cli", time.Now())
	_ = s.MarkTaskCancelled(ctx, task.ID, time.Now())

	got, err := s.ClaimNextPending(ctx, n.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil (cancelled task not claimable), got: %+v", got)
	}
}

func TestCompleteTask(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	task, _ := s.CreateTask(ctx, n.ID, "echo hi", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())
	if err := s.CompleteTask(ctx, task.ID, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTask(ctx, task.ID)
	if got.Status != store.TaskSucceeded {
		t.Fatalf("status: got %s want succeeded", got.Status)
	}
	if got.ExitCode == nil || *got.ExitCode != 0 {
		t.Fatalf("exit_code: got %v want 0", got.ExitCode)
	}
}

func TestCompleteAfterCancellingBecomesCancelled(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	task, _ := s.CreateTask(ctx, n.ID, "sleep", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())
	_ = s.MarkTaskCancelling(ctx, task.ID)
	_ = s.CompleteTask(ctx, task.ID, -1, time.Now())

	got, _ := s.GetTask(ctx, task.ID)
	if got.Status != store.TaskCancelled {
		t.Fatalf("status: got %s want cancelled", got.Status)
	}
}

func TestFindStaleRunning(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	_, _ = s.CreateTask(ctx, n.ID, "stuck", "cli", time.Now().Add(-10*time.Minute))
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now().Add(-10*time.Minute))
	// No heartbeat has been recorded.
	got, err := s.FindStaleRunning(ctx, time.Now().Add(-60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 stale, got %d", len(got))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./internal/store/... -race -v
```

Expected: FAIL with undefined task methods.

- [ ] **Step 3: Append task operations to `internal/store/sqlite.go`**

Append:

```go
// ------------- tasks -------------

func (s *sqliteStore) CreateTask(ctx context.Context, nodeID, command, createdBy string, at time.Time) (Task, error) {
	id := "task_" + shortID(24)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tasks(id, node_id, command, status, created_at, created_by)
		 VALUES(?, ?, ?, 'pending', ?, ?)`,
		id, nodeID, command, at.Unix(), nullString(createdBy))
	if err != nil {
		return Task{}, fmt.Errorf("insert task: %w", err)
	}
	return s.GetTask(ctx, id)
}

func (s *sqliteStore) GetTask(ctx context.Context, id string) (Task, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, node_id, command, status, exit_code, created_at, started_at, finished_at,
		        output_bytes, output_truncated, created_by
		 FROM tasks WHERE id = ?`, id)
	return scanTask(row)
}

func (s *sqliteStore) ListTasks(ctx context.Context, nodeID string, status TaskStatus, limit int) ([]Task, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args := []any{}
	where := ""
	if nodeID != "" {
		where += " AND node_id = ?"
		args = append(args, nodeID)
	}
	if status != "" {
		where += " AND status = ?"
		args = append(args, string(status))
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, node_id, command, status, exit_code, created_at, started_at, finished_at,
		        output_bytes, output_truncated, created_by
		 FROM tasks WHERE 1=1`+where+` ORDER BY created_at DESC LIMIT ?`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *sqliteStore) ClaimNextPending(ctx context.Context, nodeID string, at time.Time) (*Task, error) {
	// SQLite 3.35+ supports UPDATE ... RETURNING (modernc.org/sqlite bundles 3.45+).
	row := s.db.QueryRowContext(ctx,
		`UPDATE tasks
		 SET status = 'running', started_at = ?
		 WHERE id = (
		     SELECT id FROM tasks
		     WHERE node_id = ? AND status = 'pending'
		     ORDER BY created_at ASC
		     LIMIT 1
		 )
		 AND status = 'pending'
		 RETURNING id, node_id, command, status, exit_code, created_at, started_at, finished_at,
		           output_bytes, output_truncated, created_by`,
		at.Unix(), nodeID)
	t, err := scanTask(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil // no pending task
		}
		return nil, err
	}
	return &t, nil
}

func (s *sqliteStore) CompleteTask(ctx context.Context, id string, exitCode int, at time.Time) error {
	// Transition rules:
	//   running    -> succeeded (exit==0) or failed (exit!=0)
	//   cancelling -> cancelled (regardless of exit)
	//   anything else -> ErrTaskCompleted
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM tasks WHERE id = ?`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	var newStatus TaskStatus
	switch TaskStatus(status) {
	case TaskRunning:
		if exitCode == 0 {
			newStatus = TaskSucceeded
		} else {
			newStatus = TaskFailed
		}
	case TaskCancelling:
		newStatus = TaskCancelled
	default:
		return ErrTaskCompleted
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE tasks SET status = ?, exit_code = ?, finished_at = ? WHERE id = ?`,
		string(newStatus), exitCode, at.Unix(), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *sqliteStore) MarkTaskCancelling(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE tasks SET status = 'cancelling' WHERE id = ? AND status = 'running'`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotClaimable
	}
	return nil
}

func (s *sqliteStore) MarkTaskCancelled(ctx context.Context, id string, at time.Time) error {
	// Used when a pending task is cancelled before ever being claimed.
	res, err := s.db.ExecContext(ctx,
		`UPDATE tasks SET status = 'cancelled', finished_at = ?
		 WHERE id = ? AND status = 'pending'`,
		at.Unix(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotClaimable
	}
	return nil
}

func (s *sqliteStore) MarkTaskFailedLost(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE tasks SET status = 'failed', exit_code = -1, finished_at = ?
		 WHERE id = ? AND status IN ('running','cancelling')`,
		at.Unix(), id)
	return err
}

func (s *sqliteStore) PendingCancelsForNode(ctx context.Context, nodeID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM tasks WHERE node_id = ? AND status = 'cancelling'`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *sqliteStore) FindStaleRunning(ctx context.Context, olderThan time.Time) ([]Task, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT t.id, t.node_id, t.command, t.status, t.exit_code, t.created_at, t.started_at,
		        t.finished_at, t.output_bytes, t.output_truncated, t.created_by
		 FROM tasks t
		 JOIN nodes n ON n.id = t.node_id
		 WHERE t.status IN ('running','cancelling')
		   AND (n.last_seen_at IS NULL OR n.last_seen_at < ?)`,
		olderThan.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanTask(r rowScanner) (Task, error) {
	var (
		t          Task
		exitCode   sql.NullInt64
		startedAt  sql.NullInt64
		finishedAt sql.NullInt64
		createdBy  sql.NullString
		createdAt  int64
		truncated  int
	)
	if err := r.Scan(&t.ID, &t.NodeID, &t.Command, &t.Status, &exitCode, &createdAt,
		&startedAt, &finishedAt, &t.OutputBytes, &truncated, &createdBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Task{}, ErrNotFound
		}
		return Task{}, err
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	if exitCode.Valid {
		v := int(exitCode.Int64)
		t.ExitCode = &v
	}
	if startedAt.Valid {
		v := time.Unix(startedAt.Int64, 0)
		t.StartedAt = &v
	}
	if finishedAt.Valid {
		v := time.Unix(finishedAt.Int64, 0)
		t.FinishedAt = &v
	}
	t.OutputTruncated = truncated != 0
	if createdBy.Valid {
		v := createdBy.String
		t.CreatedBy = &v
	}
	return t, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./internal/store/... -race -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat(store): tasks — atomic claim, complete, mark-cancelling, find-stale

ClaimNextPending uses SQLite UPDATE ... RETURNING with a status='pending'
re-check so two concurrent polls cannot double-assign (spec §7.2,
acceptance §11 #8)."
```

---

### Task 2.6: SQLite chunk operations with output cap

**Files:**
- Modify: `internal/store/sqlite.go`
- Modify: `internal/store/sqlite_test.go`

- [ ] **Step 1: Add tests**

Append to `sqlite_test.go`:

```go
func TestAppendChunk(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	tk, _ := s.CreateTask(ctx, n.ID, "echo hi", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())

	res, err := s.AppendChunk(ctx, tk.ID, "stdout", []byte("hello\n"), time.Now(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Fatal("unexpected truncation on small chunk")
	}

	chunks, err := s.ListChunks(ctx, tk.ID, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || string(chunks[0].Data) != "hello\n" {
		t.Fatalf("unexpected chunks: %+v", chunks)
	}
}

func TestAppendChunk_OutputCap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	tk, _ := s.CreateTask(ctx, n.ID, "yes", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())

	cap := int64(16)
	// First chunk of 10 bytes: fits under the 16-byte cap.
	r1, _ := s.AppendChunk(ctx, tk.ID, "stdout", []byte("0123456789"), time.Now(), cap)
	if r1.Truncated {
		t.Fatal("chunk 1 should not be truncated")
	}
	// Second chunk of 10 bytes: only 6 bytes fit; trimmed; truncation marker appended.
	r2, _ := s.AppendChunk(ctx, tk.ID, "stdout", []byte("abcdefghij"), time.Now(), cap)
	if !r2.Truncated {
		t.Fatal("chunk 2 should have been truncated")
	}

	got, _ := s.GetTask(ctx, tk.ID)
	if !got.OutputTruncated {
		t.Fatal("task.OutputTruncated must be set")
	}
	if got.OutputBytes > cap+256 {
		// 256 is a generous envelope for the truncation marker.
		t.Fatalf("output_bytes exceeds cap+marker: %d", got.OutputBytes)
	}

	// Subsequent writes should report truncated without inserting more.
	r3, _ := s.AppendChunk(ctx, tk.ID, "stdout", []byte("more"), time.Now(), cap)
	if !r3.Truncated {
		t.Fatal("chunk 3 should see truncated")
	}
}

func TestListChunks_PerStream(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n, _ := s.CreateNode(ctx, store.NewNodeParams{Name: "n1"})
	tk, _ := s.CreateTask(ctx, n.ID, "echo", "cli", time.Now())
	_, _ = s.ClaimNextPending(ctx, n.ID, time.Now())

	_, _ = s.AppendChunk(ctx, tk.ID, "stdout", []byte("OUT"), time.Now(), 1<<20)
	_, _ = s.AppendChunk(ctx, tk.ID, "stderr", []byte("ERR"), time.Now(), 1<<20)

	out, _ := s.ListChunks(ctx, tk.ID, "stdout", 0, 100)
	if len(out) != 1 || string(out[0].Data) != "OUT" {
		t.Fatalf("stdout: %+v", out)
	}
	errc, _ := s.ListChunks(ctx, tk.ID, "stderr", 0, 100)
	if len(errc) != 1 || string(errc[0].Data) != "ERR" {
		t.Fatalf("stderr: %+v", errc)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./internal/store/... -race -v
```

Expected: FAIL.

- [ ] **Step 3: Append chunk operations to `internal/store/sqlite.go`**

Append:

```go
// ------------- chunks -------------

const truncationMarker = "\n[uncluster: output truncated at cap]\n"

func (s *sqliteStore) AppendChunk(ctx context.Context, taskID, stream string, data []byte, at time.Time, maxBytes int64) (ChunkAppendResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ChunkAppendResult{}, err
	}
	defer tx.Rollback()

	var currentBytes int64
	var alreadyTruncated int
	var status string
	if err := tx.QueryRowContext(ctx,
		`SELECT output_bytes, output_truncated, status FROM tasks WHERE id = ?`, taskID).
		Scan(&currentBytes, &alreadyTruncated, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ChunkAppendResult{}, ErrNotFound
		}
		return ChunkAppendResult{}, err
	}
	if TaskStatus(status) != TaskRunning && TaskStatus(status) != TaskCancelling {
		// Task is already terminal; drop the chunk silently but tell agent to stop.
		return ChunkAppendResult{Truncated: true}, nil
	}
	if alreadyTruncated != 0 {
		return ChunkAppendResult{Truncated: true}, nil
	}

	toInsert := data
	truncated := false
	remaining := maxBytes - currentBytes
	if remaining <= 0 {
		truncated = true
		toInsert = nil
	} else if int64(len(data)) > remaining {
		truncated = true
		toInsert = append([]byte(nil), data[:remaining]...)
	}

	// Determine next seq for this (task, stream).
	var nextSeq int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), -1) + 1 FROM task_chunks WHERE task_id = ? AND stream = ?`,
		taskID, stream).Scan(&nextSeq); err != nil {
		return ChunkAppendResult{}, err
	}

	if len(toInsert) > 0 {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO task_chunks(task_id, stream, seq, data, created_at)
			 VALUES(?, ?, ?, ?, ?)`,
			taskID, stream, nextSeq, toInsert, at.Unix()); err != nil {
			return ChunkAppendResult{}, err
		}
		nextSeq++
	}

	if truncated {
		markerBytes := []byte(truncationMarker)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO task_chunks(task_id, stream, seq, data, created_at)
			 VALUES(?, ?, ?, ?, ?)`,
			taskID, stream, nextSeq, markerBytes, at.Unix()); err != nil {
			return ChunkAppendResult{}, err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE tasks
			 SET output_bytes = output_bytes + ?,
			     output_truncated = 1
			 WHERE id = ?`,
			int64(len(toInsert))+int64(len(markerBytes)), taskID); err != nil {
			return ChunkAppendResult{}, err
		}
	} else {
		if _, err := tx.ExecContext(ctx,
			`UPDATE tasks SET output_bytes = output_bytes + ? WHERE id = ?`,
			int64(len(toInsert)), taskID); err != nil {
			return ChunkAppendResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ChunkAppendResult{}, err
	}
	return ChunkAppendResult{Truncated: truncated}, nil
}

func (s *sqliteStore) ListChunks(ctx context.Context, taskID, stream string, sinceSeq int64, limit int) ([]Chunk, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	args := []any{taskID}
	where := `task_id = ?`
	if stream != "" {
		where += ` AND stream = ?`
		args = append(args, stream)
	}
	if sinceSeq > 0 {
		where += ` AND seq >= ?`
		args = append(args, sinceSeq)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx,
		`SELECT task_id, stream, seq, data, created_at
		 FROM task_chunks WHERE `+where+`
		 ORDER BY created_at ASC, seq ASC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Chunk
	for rows.Next() {
		var c Chunk
		var createdAt int64
		if err := rows.Scan(&c.TaskID, &c.Stream, &c.Seq, &c.Data, &createdAt); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./internal/store/... -race -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat(store): task_chunks append with per-task output cap

AppendChunk enforces maxBytes server-side; once the cap is hit, trims
the incoming chunk, writes a synthetic truncation-marker chunk, and
flags tasks.output_truncated. Future chunks short-circuit and return
Truncated=true so the agent can stop flushing (spec §7.5)."
```

---

## Phase 3: Server skeleton + auth middleware + healthz

### Task 3.1: API request/response types

**Files:**
- Create: `internal/api/types.go`

- [ ] **Step 1: Write `internal/api/types.go`**

```go
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

type AgentRegisterResponse struct {
	NodeID     string `json:"node_id"`
	AgentToken string `json:"agent_token"` // plaintext, shown once
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
```

- [ ] **Step 2: Compile check**

Run:
```bash
go build ./internal/api/...
```

Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add internal/api
git commit -m "feat(api): wire types shared by server + agent + CLI"
```

---

### Task 3.2: Server struct, router, healthz handler

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/router.go`
- Create: `internal/server/handlers_health.go`
- Create: `internal/server/server_test.go`

- [ ] **Step 1: Write `internal/server/server_test.go`**

```go
package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	srv := server.New(server.Config{Store: s})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var body api.HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.OK {
		t.Fatal("ok=false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./internal/server/... -race -v
```

Expected: FAIL with "undefined: server.New".

- [ ] **Step 3: Write `internal/server/server.go`**

```go
// Package server is the Uncluster control-plane HTTP layer.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/derek-x-wang/uncluster/internal/store"
)

type Config struct {
	Store  store.Store
	Logger *slog.Logger
	// OutputCapBytes is the per-task output cap. Defaults to 10 MiB if zero.
	OutputCapBytes int64
}

type Server struct {
	cfg        Config
	dispatcher *inProcessDispatcher
	handler    http.Handler
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.OutputCapBytes == 0 {
		cfg.OutputCapBytes = 10 * 1024 * 1024
	}
	s := &Server{
		cfg:        cfg,
		dispatcher: newInProcessDispatcher(),
	}
	s.handler = s.buildRouter()
	return s
}

// Handler returns the http.Handler for mounting or testing.
func (s *Server) Handler() http.Handler { return s.handler }

// Start runs the server on addr until ctx is cancelled.
func (s *Server) Start(ctx context.Context, addr string) error {
	hs := &http.Server{
		Addr:              addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdownCtx)
	}()
	s.cfg.Logger.Info("server listening", "addr", addr)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
```

- [ ] **Step 4: Write `internal/server/router.go`**

```go
package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (s *Server) buildRouter() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger(s.cfg.Logger))

	r.Get("/healthz", s.handleHealthz)

	// Later phases mount /v1/* subrouters with auth middleware here.

	return r
}
```

- [ ] **Step 5: Write `internal/server/middleware.go`** (placeholder for request logger; auth comes in Task 3.3)

```go
package server

import (
	"log/slog"
	"net/http"
	"time"
)

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(ww, r)
			logger.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.status,
				"dur_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
```

- [ ] **Step 6: Write `internal/server/handlers_health.go`**

```go
package server

import (
	"encoding/json"
	"net/http"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/version"
)

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, api.HealthResponse{OK: true, Version: version.Version})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.ErrorResponse{Error: msg})
}
```

- [ ] **Step 7: Add dispatcher placeholder**

Create `internal/server/dispatcher.go`:

```go
package server

import "sync"

// Dispatcher is filled out properly in Phase 6; stubbed here to make the
// server struct compile.
type inProcessDispatcher struct {
	mu      sync.Mutex
	wakeups map[string]chan struct{}
}

func newInProcessDispatcher() *inProcessDispatcher {
	return &inProcessDispatcher{wakeups: make(map[string]chan struct{})}
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run:
```bash
go test ./internal/server/... -race -v
```

Expected: `TestHealthz` PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/server
git commit -m "feat(server): skeleton — chi router, request logger, healthz

Dispatcher is a stub here; fleshed out in Phase 6 when long-poll lands."
```

---

### Task 3.3: Auth middleware + token verification path

**Files:**
- Create: `internal/server/middleware_auth.go`
- Create: `internal/server/middleware_auth_test.go`

- [ ] **Step 1: Write `internal/server/middleware_auth_test.go`**

```go
package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func newAuthTestSetup(t *testing.T) (*httptest.Server, store.Store, token.Token) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	tok, _ := token.Generate(token.KindCLI)
	hash, _ := token.HashSecret(tok.Secret)
	// Poke the token directly into the store with our desired ID.
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		tok.ID, store.TokenCLI, nil, hash, "test"); err != nil {
		t.Fatal(err)
	}

	srv := server.New(server.Config{Store: st})
	// Mount a protected probe route for testing.
	probe := server.MountProbeRoute(srv)
	ts := httptest.NewServer(probe)
	t.Cleanup(ts.Close)
	return ts, st, tok
}

func TestAuthMiddleware_AcceptsValidToken(t *testing.T) {
	ts, _, tok := newAuthTestSetup(t)
	req, _ := http.NewRequest("GET", ts.URL+"/__probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_RejectsMissing(t *testing.T) {
	ts, _, _ := newAuthTestSetup(t)
	resp, _ := http.Get(ts.URL + "/__probe")
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_RejectsWrongSecret(t *testing.T) {
	ts, _, tok := newAuthTestSetup(t)
	bad := "uct_cli_" + tok.ID + "_" + strings("A", 52) // wrong secret
	req, _ := http.NewRequest("GET", ts.URL+"/__probe", nil)
	req.Header.Set("Authorization", "Bearer "+bad)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func strings(c string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += c
	}
	return out
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./internal/server/... -race -v -run TestAuth
```

Expected: FAIL with undefined references.

- [ ] **Step 3: Add `TestInsertHook` to the store (for tests only)**

Append to `internal/store/sqlite.go`:

```go
// TestInsertHook is a test-only seam for fixtures. Not exported in the
// Store interface; tests type-assert against the concrete SQLite impl.
type TestInsertHook interface {
	InsertTokenWithID(ctx context.Context, id string, kind TokenKind, nodeID *string, secretHash, label string) (Token, error)
}

func (s *sqliteStore) InsertTokenWithID(ctx context.Context, id string, kind TokenKind, nodeID *string, secretHash, label string) (Token, error) {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens(id, kind, node_id, secret_hash, label, created_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		id, string(kind), nodeID, secretHash, label, now.Unix())
	if err != nil {
		return Token{}, err
	}
	return s.GetTokenByID(ctx, id)
}
```

- [ ] **Step 4: Write `internal/server/middleware_auth.go`**

```go
package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

type ctxKey string

const (
	ctxAuthedToken ctxKey = "authed_token"
	ctxAuthedNode  ctxKey = "authed_node"
)

func (s *Server) requireAuth(requiredKind store.TokenKind) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerFrom(r.Header.Get("Authorization"))
			if raw == "" {
				writeError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			parsed, err := token.Parse(raw)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "malformed token")
				return
			}
			row, err := s.cfg.Store.GetTokenByID(r.Context(), parsed.ID)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "unknown token")
				return
			}
			if store.TokenKind(parsed.Kind) != row.Kind {
				writeError(w, http.StatusUnauthorized, "kind mismatch")
				return
			}
			if row.Kind != requiredKind {
				writeError(w, http.StatusUnauthorized, "wrong token kind for this route")
				return
			}
			if row.RevokedAt != nil {
				writeError(w, http.StatusUnauthorized, "token revoked")
				return
			}
			if row.ExpiresAt != nil && row.ExpiresAt.Before(time.Now()) {
				writeError(w, http.StatusUnauthorized, "token expired")
				return
			}
			if row.Kind == store.TokenJoin && row.UsedAt != nil {
				writeError(w, http.StatusUnauthorized, "join token already used")
				return
			}
			ok, err := token.VerifySecret(parsed.Secret, row.SecretHash)
			if err != nil || !ok {
				writeError(w, http.StatusUnauthorized, "secret mismatch")
				return
			}
			ctx := context.WithValue(r.Context(), ctxAuthedToken, row)
			// For agent tokens, also carry the node and reject revoked nodes.
			if row.Kind == store.TokenAgent {
				if row.NodeID == nil {
					writeError(w, http.StatusUnauthorized, "agent token has no node")
					return
				}
				node, err := s.cfg.Store.GetNode(r.Context(), *row.NodeID)
				if err != nil || node.Status == store.NodeRevoked {
					writeError(w, http.StatusUnauthorized, "node revoked")
					return
				}
				ctx = context.WithValue(ctx, ctxAuthedNode, node)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerFrom(h string) string {
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(h[len("Bearer "):])
}

// ErrAuthFailed is exported for tests / handlers that want to detect auth
// problems distinctly from store/not-found.
var ErrAuthFailed = errors.New("auth: failed")
```

- [ ] **Step 5: Add a test-only probe mount**

Append to `internal/server/server.go`:

```go
// MountProbeRoute is a test-only helper: returns a handler with a route
// "/__probe" that requires a CLI bearer token. Used by middleware tests.
func MountProbeRoute(s *Server) http.Handler {
	r := http.NewServeMux()
	r.Handle("/__probe", s.requireAuth(store.TokenCLI)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })))
	return r
}
```

Also add the `store` import to that file if it isn't already present.

- [ ] **Step 6: Run tests to verify they pass**

Run:
```bash
go test ./internal/server/... -race -v
```

Expected: all auth tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/server internal/store
git commit -m "feat(server): bearer-token auth middleware

Parses uct_<kind>_<id>_<secret>, looks up row by id (indexed O(1)),
verifies secret via argon2, checks kind/expiry/revocation. For agent
tokens also rejects if node.status='revoked' (defense in depth)."
```

---

**SP1 reached:** Server binary starts, serves `/healthz`, auth middleware works end-to-end with tokens inserted directly into the DB. Next phase adds CLI commands to actually mint/list/revoke tokens.

---

## Phase 4: Server CLI + token HTTP handlers + `uncluster server`

### Task 4.1: Token HTTP handlers (create / list / revoke)

**Files:**
- Create: `internal/server/handlers_tokens.go`
- Modify: `internal/server/router.go`

- [ ] **Step 1: Write handler tests in `internal/server/handlers_tokens_test.go`**

```go
package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func seedCLIToken(t *testing.T, st store.Store) (string, string) {
	t.Helper()
	tok, _ := token.Generate(token.KindCLI)
	hash, _ := token.HashSecret(tok.Secret)
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		tok.ID, store.TokenCLI, nil, hash, "seed")
	return tok.String(), tok.ID
}

func TestCreateAndListTokens(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	cli, _ := seedCLIToken(t, st), ""

	body, _ := json.Marshal(api.CreateTokenRequest{Kind: "join", Label: "new-node"})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cli)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("create: %v status=%d", err, resp.StatusCode)
	}
	var got api.CreateTokenResponse
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.ID == "" || got.Token == "" {
		t.Fatalf("empty response: %+v", got)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/v1/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+cli)
	resp, _ = http.DefaultClient.Do(req)
	var list []api.TokenSummary
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if len(list) < 2 { // seeded + the one we just made
		t.Fatalf("want ≥2 tokens, got %d", len(list))
	}
}

func httpTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}
```

Add `"net/http/httptest"` import.

- [ ] **Step 2: Write `internal/server/handlers_tokens.go`**

```go
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req api.CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	var kind store.TokenKind
	switch req.Kind {
	case "join":
		kind = store.TokenJoin
	case "cli":
		kind = store.TokenCLI
	default:
		writeError(w, http.StatusBadRequest, "kind must be join or cli")
		return
	}

	tok, err := token.Generate(token.Kind(kind))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate: "+err.Error())
		return
	}
	hash, err := token.HashSecret(tok.Secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash: "+err.Error())
		return
	}
	var expiresAt *time.Time
	switch {
	case req.ExpiresAt != nil:
		v := time.Unix(*req.ExpiresAt, 0)
		expiresAt = &v
	case kind == store.TokenJoin:
		v := time.Now().Add(15 * time.Minute)
		expiresAt = &v
	}
	row, err := s.cfg.Store.CreateToken(r.Context(), store.NewTokenParams{
		Kind: kind, SecretHash: hash, Label: req.Label, ExpiresAt: expiresAt,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create: "+err.Error())
		return
	}
	// Rewrite the token string's ID to match the DB row's ID.
	tok.ID = row.ID
	writeJSON(w, http.StatusOK, api.CreateTokenResponse{ID: row.ID, Token: tok.String()})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := s.cfg.Store.ListTokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.TokenSummary, 0, len(rows))
	for _, t := range rows {
		out = append(out, api.TokenSummary{
			ID: t.ID, Kind: string(t.Kind), Label: t.Label,
			NodeID:    t.NodeID,
			CreatedAt: t.CreatedAt.Unix(),
			ExpiresAt: api.TimePtr(t.ExpiresAt),
			UsedAt:    api.TimePtr(t.UsedAt),
			RevokedAt: api.TimePtr(t.RevokedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.cfg.Store.RevokeToken(r.Context(), id, time.Now()); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

**IMPORTANT:** the `CreateToken` store method auto-generates an ID via `shortID`. Since the token string embeds that ID, we need the inserted ID. The simplest fix: have the handler generate the token first, call a `store.CreateTokenWithID` method, and share the same ID.

Adjust: add `CreateTokenWithID` to `store.TestInsertHook` (but it's cleaner to put it on the main `Store` interface). Let's add a second param path:

Modify `internal/store/store.go` — extend `NewTokenParams`:

```go
type NewTokenParams struct {
	ID         string // if empty, the store generates one
	Kind       TokenKind
	NodeID     *string
	SecretHash string
	Label      string
	ExpiresAt  *time.Time
}
```

And in `internal/store/sqlite.go`, `CreateToken`:

```go
func (s *sqliteStore) CreateToken(ctx context.Context, p NewTokenParams) (Token, error) {
	id := p.ID
	if id == "" {
		id = shortID(16)
	}
	// ... rest unchanged
}
```

And in the handler, set `p.ID = tok.ID` before calling `CreateToken`.

- [ ] **Step 3: Mount the routes**

Append to `internal/server/router.go` (inside `buildRouter`, before `return r`):

```go
	r.Route("/v1", func(v1 chi.Router) {
		v1.Group(func(cli chi.Router) {
			cli.Use(s.requireAuth(store.TokenCLI))
			cli.Post("/tokens", s.handleCreateToken)
			cli.Get("/tokens", s.handleListTokens)
			cli.Delete("/tokens/{id}", s.handleRevokeToken)
		})
	})
```

Add import `"github.com/derek-x-wang/uncluster/internal/store"`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./... -race -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server internal/store
git commit -m "feat(server): /v1/tokens create/list/revoke under CLI auth"
```

---

### Task 4.2: `uncluster server start` + `uncluster server token` CLI

**Files:**
- Create: `internal/cli/server_cmd.go`
- Create: `internal/cli/tokenio.go`
- Create: `internal/cli/httpclient.go`
- Create: `internal/cli/config_cmd.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Write `internal/cli/tokenio.go`** (the `--token-stdin` / env var helper)

```go
package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadSecretToken returns a token read from one of:
//   - --token-stdin flag: reads the first line of os.Stdin
//   - UNCLUSTER_TOKEN env var (only if --token-stdin was not set)
// Returns an error if both are absent or if a bare --token=... flag is passed.
func ReadSecretToken(tokenStdin bool) (string, error) {
	if tokenStdin {
		rd := bufio.NewReader(os.Stdin)
		line, err := rd.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return "", fmt.Errorf("empty token on stdin")
		}
		return line, nil
	}
	if v, ok := os.LookupEnv("UNCLUSTER_TOKEN"); ok && v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no token provided; use --token-stdin or set UNCLUSTER_TOKEN (never --token=<value>)")
}
```

- [ ] **Step 2: Write `internal/cli/httpclient.go`**

```go
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewClient(baseURL, tok string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   tok,
		HTTP:    &http.Client{Timeout: 35 * time.Second}, // long enough for SSE-less requests
	}
}

func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
```

- [ ] **Step 3: Write `internal/cli/config_cmd.go`**

```go
package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
)

type CLIConfig struct {
	Server string `toml:"server"`
	Token  string `toml:"token"`
}

func cliConfigPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "uncluster", "cli.toml"), nil
}

func LoadCLIConfig() (CLIConfig, error) {
	var cfg CLIConfig
	p, err := cliConfigPath()
	if err != nil {
		return cfg, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	_, err = toml.Decode(string(b), &cfg)
	return cfg, err
}

func SaveCLIConfig(cfg CLIConfig) error {
	p, err := cliConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(cfg)
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Read / write ~/.config/uncluster/cli.toml"}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the CLI config (token is masked)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "server = %q\n", cfg.Server)
			if cfg.Token != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "token  = %q\n", "uct_***_"+truncID(cfg.Token))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "token  = (unset)")
			}
			return nil
		},
	})

	var setStdin bool
	set := &cobra.Command{
		Use:   "set [key=value]",
		Short: "Set a config value. Use --stdin for secrets (token).",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			if setStdin {
				rd := bufio.NewReader(os.Stdin)
				line, err := rd.ReadString('\n')
				if err != nil && err != io.EOF {
					return err
				}
				cfg.Token = strings.TrimSpace(line)
			}
			for _, kv := range args {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("bad argument %q; want key=value", kv)
				}
				switch parts[0] {
				case "server":
					cfg.Server = parts[1]
				case "token":
					return fmt.Errorf("refusing to read 'token' from argv; use `config set token --stdin`")
				default:
					return fmt.Errorf("unknown key %q", parts[0])
				}
			}
			return SaveCLIConfig(cfg)
		},
	}
	set.Flags().BoolVar(&setStdin, "stdin", false, "read the token from stdin (first line)")
	cmd.AddCommand(set)
	return cmd
}

func truncID(full string) string {
	// uct_<kind>_<id>_<secret>: keep only id tail chars.
	parts := strings.Split(full, "_")
	if len(parts) >= 3 && len(parts[2]) >= 4 {
		return parts[2][len(parts[2])-4:]
	}
	return "****"
}
```

- [ ] **Step 4: Write `internal/cli/server_cmd.go`**

```go
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "server", Short: "Run and manage the Uncluster control plane"}

	var addr, dbPath string
	start := &cobra.Command{
		Use:   "start",
		Short: "Start the control plane",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dbPath == "" {
				dir := os.Getenv("XDG_DATA_HOME")
				if dir == "" {
					home, _ := os.UserHomeDir()
					dir = filepath.Join(home, ".local", "share")
				}
				_ = os.MkdirAll(filepath.Join(dir, "uncluster"), 0o700)
				dbPath = filepath.Join(dir, "uncluster", "uncluster.db")
			}
			st, err := store.OpenSQLite(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer st.Close()

			srv := server.New(server.Config{Store: st})
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return srv.Start(ctx, addr)
		},
	}
	start.Flags().StringVar(&addr, "addr", ":7777", "listen address")
	start.Flags().StringVar(&dbPath, "db", "", "sqlite db path (default: $XDG_DATA_HOME/uncluster/uncluster.db)")
	cmd.AddCommand(start)

	// token subcommands — uses the HTTP API; needs server+cli-token config.
	tok := &cobra.Command{Use: "token", Short: "Manage tokens (on a running server)"}

	var kind, label string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a token (join or cli). Prints plaintext ONCE.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; run `uncluster config set server=URL` and `uncluster config set token --stdin`")
			}
			client := NewClient(cfg.Server, cfg.Token)
			var out api.CreateTokenResponse
			if err := client.Do(cmd.Context(), "POST", "/v1/tokens",
				api.CreateTokenRequest{Kind: kind, Label: label}, &out); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "token: %s\n", out.Token)
			fmt.Fprintf(cmd.OutOrStdout(), "id:    %s\n", out.ID)
			return nil
		},
	}
	create.Flags().StringVar(&kind, "kind", "", "join | cli (required)")
	create.Flags().StringVar(&label, "label", "", "human-readable note")
	_ = create.MarkFlagRequired("kind")
	tok.AddCommand(create)

	ls := &cobra.Command{
		Use:   "ls",
		Short: "List tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			var out []api.TokenSummary
			if err := client.Do(cmd.Context(), "GET", "/v1/tokens", nil, &out); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%-18s %-6s %-20s %-10s\n", "ID", "KIND", "LABEL", "STATE")
			for _, t := range out {
				state := "active"
				switch {
				case t.RevokedAt != nil:
					state = "revoked"
				case t.UsedAt != nil:
					state = "used"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-18s %-6s %-20s %-10s\n", t.ID, t.Kind, t.Label, state)
			}
			return nil
		},
	}
	tok.AddCommand(ls)

	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			return client.Do(cmd.Context(), "DELETE", "/v1/tokens/"+args[0], nil, nil)
		},
	}
	tok.AddCommand(revoke)

	cmd.AddCommand(tok)
	return cmd
}
```

- [ ] **Step 5: Wire into root**

Modify `internal/cli/root.go` — add inside `NewRoot` before `return root`:

```go
	root.AddCommand(newServerCmd())
	root.AddCommand(newConfigCmd())
```

- [ ] **Step 6: Smoke test**

Run:
```bash
make build
./uncluster server start --addr :17777 --db /tmp/u-smoke.db &
SERVER_PID=$!
sleep 1

# Bootstrap a CLI token by directly poking the DB (server-side mode only — same host).
# For the smoke test, use a test helper: one-off SQL.
go run ./cmd/uncluster server start --addr :17777 &
# Actually the CLI can't mint its first token without a token. Seed manually:
sqlite3 /tmp/u-smoke.db <<'SQL'
INSERT INTO tokens(id, kind, secret_hash, label, created_at)
VALUES ('seedcli000000001', 'cli', 'seed-hash', 'smoke', strftime('%s','now'));
SQL

# For a real bootstrap we need a `uncluster server bootstrap` command — see Task 4.3.
kill $SERVER_PID || true
```

Expected: binary runs, stops cleanly. (Don't worry if the token seed is awkward; Task 4.3 fixes the bootstrap story.)

- [ ] **Step 7: Commit**

```bash
git add internal/cli
git commit -m "feat(cli): uncluster server start + server token {create,ls,revoke} + config"
```

---

### Task 4.3: First-CLI-token bootstrap

**Files:**
- Modify: `internal/cli/server_cmd.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/handlers_tokens.go`

There's a chicken-and-egg: creating the first CLI token via the API requires a CLI token. Fix by giving `uncluster server` a direct-DB path.

- [ ] **Step 1: Add a `bootstrap` subcommand under `server`**

Append inside `newServerCmd` after `tok.AddCommand(revoke)`:

```go
	var bsLabel string
	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Mint the first CLI token by writing directly to the DB. Use only once per install.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := dbPath
			if path == "" {
				home, _ := os.UserHomeDir()
				path = filepath.Join(home, ".local", "share", "uncluster", "uncluster.db")
			}
			st, err := store.OpenSQLite(path)
			if err != nil {
				return err
			}
			defer st.Close()

			tkn, err := token.Generate(token.KindCLI)
			if err != nil {
				return err
			}
			hash, err := token.HashSecret(tkn.Secret)
			if err != nil {
				return err
			}
			row, err := st.CreateToken(cmd.Context(), store.NewTokenParams{
				ID: tkn.ID, Kind: store.TokenCLI, SecretHash: hash, Label: bsLabel,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "token: %s\n", tkn.String())
			fmt.Fprintf(cmd.OutOrStdout(), "id:    %s\n", row.ID)
			fmt.Fprintln(cmd.OutOrStdout(), "(shown ONCE — copy it now)")
			return nil
		},
	}
	bootstrap.Flags().StringVar(&dbPath, "db", "", "sqlite db path (default: $XDG_DATA_HOME/uncluster/uncluster.db)")
	bootstrap.Flags().StringVar(&bsLabel, "label", "bootstrap", "label for the minted token")
	cmd.AddCommand(bootstrap)
```

Add imports: `"github.com/derek-x-wang/uncluster/internal/token"` (and `"path/filepath"`, `"os"` if missing).

- [ ] **Step 2: Smoke test**

Run:
```bash
rm -f /tmp/u-smoke.db
make build
./uncluster server bootstrap --db /tmp/u-smoke.db
```

Expected: prints a `uct_cli_...` token and id.

- [ ] **Step 3: Commit**

```bash
git add internal/cli
git commit -m "feat(cli): uncluster server bootstrap — mint first CLI token via direct DB"
```

---

### Task 4.4: OpenAPI YAML sync — add /v1/tokens

**Files:**
- Modify: `api/openapi.yaml`

- [ ] **Step 1: Append paths under `paths:`**

```yaml
  /v1/tokens:
    post:
      summary: Create a token (join or cli)
      security: [{ bearerAuth: [] }]
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/CreateTokenRequest" }
      responses:
        "200":
          description: Token created (plaintext returned exactly once)
          content:
            application/json:
              schema: { $ref: "#/components/schemas/CreateTokenResponse" }
    get:
      summary: List tokens (metadata only; never plaintext)
      security: [{ bearerAuth: [] }]
      responses:
        "200":
          description: OK
          content:
            application/json:
              schema:
                type: array
                items: { $ref: "#/components/schemas/TokenSummary" }

  /v1/tokens/{id}:
    delete:
      summary: Revoke a token
      security: [{ bearerAuth: [] }]
      parameters:
        - in: path
          name: id
          required: true
          schema: { type: string }
      responses:
        "204": { description: Revoked }
        "404": { description: Not found }
```

Under `components.schemas:`:

```yaml
    CreateTokenRequest:
      type: object
      required: [kind]
      properties:
        kind: { type: string, enum: [join, cli] }
        label: { type: string }
        expires_at:
          type: integer
          format: int64
          description: Unix seconds; omitted for CLI tokens means "no expiry"; omitted for join tokens defaults to now+15m.
    CreateTokenResponse:
      type: object
      required: [id, token]
      properties:
        id: { type: string }
        token: { type: string }
    TokenSummary:
      type: object
      properties:
        id: { type: string }
        kind: { type: string }
        label: { type: string }
        node_id: { type: string, nullable: true }
        created_at: { type: integer, format: int64 }
        expires_at: { type: integer, format: int64, nullable: true }
        used_at: { type: integer, format: int64, nullable: true }
        revoked_at: { type: integer, format: int64, nullable: true }
```

- [ ] **Step 2: Commit**

```bash
git add api/openapi.yaml
git commit -m "docs(api): document /v1/tokens in openapi.yaml"
```

---

## Phase 5: Node + agent registration + heartbeat HTTP

### Task 5.1: Node + agent-register + heartbeat handlers (server)

**Files:**
- Create: `internal/server/handlers_agent.go`
- Create: `internal/server/handlers_nodes.go`
- Modify: `internal/server/router.go`
- Create: `internal/server/handlers_agent_test.go`

- [ ] **Step 1: Write `handlers_agent.go`**

```go
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req api.AgentRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" || req.JoinToken == "" {
		writeError(w, http.StatusBadRequest, "name and join_token required")
		return
	}

	parsed, err := token.Parse(req.JoinToken)
	if err != nil || parsed.Kind != token.Kind(store.TokenJoin) {
		writeError(w, http.StatusUnauthorized, "invalid join token")
		return
	}
	row, err := s.cfg.Store.GetTokenByID(r.Context(), parsed.ID)
	if err != nil || row.Kind != store.TokenJoin {
		writeError(w, http.StatusUnauthorized, "unknown join token")
		return
	}
	if row.UsedAt != nil {
		writeError(w, http.StatusUnauthorized, "join token already used")
		return
	}
	if row.RevokedAt != nil {
		writeError(w, http.StatusUnauthorized, "join token revoked")
		return
	}
	if row.ExpiresAt != nil && row.ExpiresAt.Before(time.Now()) {
		writeError(w, http.StatusUnauthorized, "join token expired")
		return
	}
	ok, err := token.VerifySecret(parsed.Secret, row.SecretHash)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "secret mismatch")
		return
	}

	metaJSON, _ := json.Marshal(req.Metadata)
	node, err := s.cfg.Store.CreateNode(r.Context(), store.NewNodeParams{
		Name: req.Name, Metadata: string(metaJSON),
	})
	if err != nil {
		if err == store.ErrNameTaken {
			writeError(w, http.StatusConflict, "name already in use")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	agentTok, err := token.Generate(token.KindAgent)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hash, _ := token.HashSecret(agentTok.Secret)
	nid := node.ID
	if _, err := s.cfg.Store.CreateToken(r.Context(), store.NewTokenParams{
		ID: agentTok.ID, Kind: store.TokenAgent, NodeID: &nid, SecretHash: hash, Label: "agent:" + node.Name,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.cfg.Store.MarkJoinTokenUsed(r.Context(), row.ID, time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, api.AgentRegisterResponse{
		NodeID: node.ID, AgentToken: agentTok.String(),
	})
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	node := r.Context().Value(ctxAuthedNode).(store.Node)
	var req api.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	metaJSON, _ := json.Marshal(req.Metadata)
	if err := s.cfg.Store.UpdateNodeHeartbeat(r.Context(), node.ID, string(metaJSON), time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cancels, _ := s.cfg.Store.PendingCancelsForNode(r.Context(), node.ID)
	writeJSON(w, http.StatusOK, api.HeartbeatResponse{CancelTaskIDs: cancels})
}
```

- [ ] **Step 2: Write `handlers_nodes.go`**

```go
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
)

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.cfg.Store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.NodeSummary, 0, len(nodes))
	for _, n := range nodes {
		var meta map[string]any
		_ = json.Unmarshal([]byte(n.Metadata), &meta)
		out = append(out, api.NodeSummary{
			ID: n.ID, Name: n.Name, Status: string(n.Status),
			CreatedAt: n.CreatedAt.Unix(), LastSeenAt: api.TimePtr(n.LastSeenAt),
			Metadata: meta,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	idOrName := chi.URLParam(r, "id")
	node, err := s.cfg.Store.GetNode(r.Context(), idOrName)
	if err != nil {
		node, err = s.cfg.Store.GetNodeByName(r.Context(), idOrName)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var meta map[string]any
	_ = json.Unmarshal([]byte(node.Metadata), &meta)
	writeJSON(w, http.StatusOK, api.NodeSummary{
		ID: node.ID, Name: node.Name, Status: string(node.Status),
		CreatedAt: node.CreatedAt.Unix(), LastSeenAt: api.TimePtr(node.LastSeenAt),
		Metadata: meta,
	})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	idOrName := chi.URLParam(r, "id")
	node, err := s.cfg.Store.GetNode(r.Context(), idOrName)
	if err != nil {
		node, err = s.cfg.Store.GetNodeByName(r.Context(), idOrName)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err := s.cfg.Store.RevokeNode(r.Context(), node.ID, time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 3: Mount routes**

In `internal/server/router.go`, inside the `/v1` block, add alongside the CLI group:

```go
		v1.Group(func(agent chi.Router) {
			// /v1/agent/register is unauthenticated but validates the join token in-handler.
			agent.Post("/agent/register", s.handleAgentRegister)
		})
		v1.Group(func(agent chi.Router) {
			agent.Use(s.requireAuth(store.TokenAgent))
			agent.Post("/agent/heartbeat", s.handleAgentHeartbeat)
		})
		v1.Group(func(cli chi.Router) {
			cli.Use(s.requireAuth(store.TokenCLI))
			cli.Get("/nodes", s.handleListNodes)
			cli.Get("/nodes/{id}", s.handleGetNode)
			cli.Delete("/nodes/{id}", s.handleDeleteNode)
		})
```

- [ ] **Step 4: Write tests in `handlers_agent_test.go`**

```go
package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func mintJoinToken(t *testing.T, st store.Store) string {
	t.Helper()
	jt, _ := token.Generate(token.KindJoin)
	hash, _ := token.HashSecret(jt.Secret)
	if _, err := st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		jt.ID, store.TokenJoin, nil, hash, "join"); err != nil {
		t.Fatal(err)
	}
	return jt.String()
}

func TestAgentRegisterAndHeartbeat(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httpTestServer(t, srv.Handler())

	jt := mintJoinToken(t, st)

	body, _ := json.Marshal(api.AgentRegisterRequest{
		JoinToken: jt, Name: "mac", Metadata: map[string]any{"os": "darwin"},
	})
	resp, err := http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("register: %v status=%d", err, resp.StatusCode)
	}
	var reg api.AgentRegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	if reg.AgentToken == "" || reg.NodeID == "" {
		t.Fatalf("empty response: %+v", reg)
	}

	// Heartbeat with the returned agent token.
	hbody, _ := json.Marshal(api.HeartbeatRequest{Metadata: map[string]any{"load": 0.5}})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/agent/heartbeat", bytes.NewReader(hbody))
	req.Header.Set("Authorization", "Bearer "+reg.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("heartbeat: %v status=%d", err, resp.StatusCode)
	}

	// Using the join token twice must fail.
	resp, _ = http.Post(ts.URL+"/v1/agent/register", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 401 {
		t.Fatalf("reuse: status=%d", resp.StatusCode)
	}
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./... -race -v
```

Expected: all PASS.

- [ ] **Step 6: Append to `api/openapi.yaml`**

Under `paths:`:

```yaml
  /v1/agent/register:
    post:
      summary: Exchange a one-time join token for a long-lived agent token
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/AgentRegisterRequest" }
      responses:
        "200":
          content:
            application/json:
              schema: { $ref: "#/components/schemas/AgentRegisterResponse" }
        "401": { description: invalid/used/expired join token }
        "409": { description: node name already in use }

  /v1/agent/heartbeat:
    post:
      summary: Report node liveness and metadata; receive cancel instructions
      security: [{ bearerAuth: [] }]
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/HeartbeatRequest" }
      responses:
        "200":
          content:
            application/json:
              schema: { $ref: "#/components/schemas/HeartbeatResponse" }

  /v1/nodes:
    get:
      summary: List registered nodes
      security: [{ bearerAuth: [] }]
      responses:
        "200":
          content:
            application/json:
              schema:
                type: array
                items: { $ref: "#/components/schemas/NodeSummary" }

  /v1/nodes/{id}:
    get:
      summary: Get a single node by id or name
      security: [{ bearerAuth: [] }]
      parameters:
        - in: path
          name: id
          required: true
          schema: { type: string }
      responses:
        "200":
          content:
            application/json:
              schema: { $ref: "#/components/schemas/NodeSummary" }
        "404": { description: not found }
    delete:
      summary: Revoke (remove) a node; frees its name for reuse
      security: [{ bearerAuth: [] }]
      parameters:
        - in: path
          name: id
          required: true
          schema: { type: string }
      responses:
        "204": { description: revoked }
        "404": { description: not found }
```

Add schemas under `components.schemas:` (reuse the types from `internal/api/types.go` structure):

```yaml
    AgentRegisterRequest:
      type: object
      required: [join_token, name]
      properties:
        join_token: { type: string }
        name: { type: string }
        metadata: { type: object, additionalProperties: true }
    AgentRegisterResponse:
      type: object
      required: [node_id, agent_token]
      properties:
        node_id: { type: string }
        agent_token: { type: string }
    HeartbeatRequest:
      type: object
      properties:
        metadata: { type: object, additionalProperties: true }
    HeartbeatResponse:
      type: object
      properties:
        cancel_task_ids:
          type: array
          items: { type: string }
    NodeSummary:
      type: object
      properties:
        id: { type: string }
        name: { type: string }
        status: { type: string, enum: [online, offline, revoked] }
        created_at: { type: integer, format: int64 }
        last_seen_at: { type: integer, format: int64, nullable: true }
        metadata: { type: object, additionalProperties: true }
```

- [ ] **Step 7: Commit**

```bash
git add internal/server api/openapi.yaml
git commit -m "feat(server): agent register, agent heartbeat, nodes endpoints"
```

---

## Phase 6: Agent — config, metrics, join, heartbeat, poll

### Task 6.1: Agent config file

**Files:**
- Create: `internal/agent/config.go`
- Create: `internal/agent/config_test.go`

- [ ] **Step 1: Write test**

```go
package agent_test

import (
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/agent"
)

func TestConfigRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.toml")
	in := agent.Config{
		Server: "https://x", NodeID: "node_a", NodeName: "mac", AgentToken: "uct_agent_xxx_yyy",
	}
	if err := agent.SaveConfig(p, in); err != nil {
		t.Fatal(err)
	}
	out, err := agent.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}
```

- [ ] **Step 2: Implement**

`internal/agent/config.go`:

```go
package agent

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server     string `toml:"server"`
	NodeID     string `toml:"node_id"`
	NodeName   string `toml:"node_name"`
	AgentToken string `toml:"agent_token"`
}

func DefaultConfigPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "uncluster", "agent.toml"), nil
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	_, err = toml.Decode(string(b), &cfg)
	return cfg, err
}

func SaveConfig(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(cfg)
}
```

- [ ] **Step 3: Run tests and commit**

```bash
go test ./internal/agent/... -race -v
git add internal/agent
git commit -m "feat(agent): config read/write to ~/.config/uncluster/agent.toml"
```

---

### Task 6.2: Agent HTTP client + metrics

**Files:**
- Create: `internal/agent/http.go`
- Create: `internal/agent/metrics.go`

- [ ] **Step 1: Write `metrics.go`**

```go
package agent

import (
	"runtime"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

func CollectMetrics() map[string]any {
	out := map[string]any{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpu_cores":  runtime.NumCPU(),
		"go_version": runtime.Version(),
	}
	if info, err := host.Info(); err == nil {
		out["hostname"] = info.Hostname
		out["platform"] = info.Platform
		out["kernel"] = info.KernelVersion
		out["uptime_s"] = info.Uptime
	}
	if v, err := mem.VirtualMemory(); err == nil {
		out["mem_total"] = v.Total
		out["mem_available"] = v.Available
	}
	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		out["cpu_pct"] = pct[0]
	}
	if l, err := load.Avg(); err == nil {
		out["load_1"] = l.Load1
		out["load_5"] = l.Load5
		out["load_15"] = l.Load15
	}
	return out
}
```

- [ ] **Step 2: Write `http.go`**

```go
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
)

type ServerClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewServerClient(baseURL, tok string) *ServerClient {
	return &ServerClient{
		BaseURL: baseURL,
		Token:   tok,
		// Long enough for the 30s long-poll + headroom.
		HTTP: &http.Client{Timeout: 45 * time.Second},
	}
}

var ErrUnauthorized = errors.New("agent: unauthorized")

func (c *ServerClient) do(ctx context.Context, method, path string, in any, out any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 {
		_ = resp.Body.Close()
		return nil, ErrUnauthorized
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s %s: %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			return nil, err
		}
	}
	return resp, nil
}

func (c *ServerClient) Register(ctx context.Context, req api.AgentRegisterRequest) (api.AgentRegisterResponse, error) {
	var out api.AgentRegisterResponse
	_, err := c.do(ctx, "POST", "/v1/agent/register", req, &out)
	return out, err
}

func (c *ServerClient) Heartbeat(ctx context.Context, metadata map[string]any) (api.HeartbeatResponse, error) {
	var out api.HeartbeatResponse
	_, err := c.do(ctx, "POST", "/v1/agent/heartbeat", api.HeartbeatRequest{Metadata: metadata}, &out)
	return out, err
}

func (c *ServerClient) NextTask(ctx context.Context) (*api.NextTaskResponse, error) {
	// Uses a separate HTTP client with longer timeout for long-poll.
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/v1/agent/next-task", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	lpClient := &http.Client{Timeout: 45 * time.Second}
	resp, err := lpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode == 204 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("next-task: %d: %s", resp.StatusCode, string(b))
	}
	var out api.NextTaskResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *ServerClient) UploadChunk(ctx context.Context, taskID, stream string, data []byte) (api.ChunkUploadResponse, error) {
	var out api.ChunkUploadResponse
	_, err := c.do(ctx, "POST", "/v1/agent/tasks/"+taskID+"/chunks",
		api.ChunkUploadRequest{Stream: stream, Data: data}, &out)
	return out, err
}

func (c *ServerClient) Complete(ctx context.Context, taskID string, exitCode int) error {
	_, err := c.do(ctx, "POST", "/v1/agent/tasks/"+taskID+"/complete",
		api.CompleteRequest{ExitCode: exitCode}, nil)
	return err
}
```

- [ ] **Step 3: Commit**

```bash
go build ./...
git add internal/agent
git commit -m "feat(agent): http client + metrics collection via gopsutil"
```

---

### Task 6.3: `uncluster agent join` CLI

**Files:**
- Create: `internal/cli/agent_cmd.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Write `agent_cmd.go`**

```go
package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Run or install the Uncluster node agent"}

	var server, name string
	var tokenStdin bool
	join := &cobra.Command{
		Use:   "join",
		Short: "Exchange a join token for a long-lived agent credential",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if server == "" || name == "" {
				return fmt.Errorf("--server and --name are required")
			}
			tok, err := ReadSecretToken(tokenStdin)
			if err != nil {
				return err
			}

			client := agent.NewServerClient(server, "")
			resp, err := client.Register(cmd.Context(), api.AgentRegisterRequest{
				JoinToken: tok, Name: name, Metadata: agent.CollectMetrics(),
			})
			if err != nil {
				return err
			}
			p, err := agent.DefaultConfigPath()
			if err != nil {
				return err
			}
			cfg := agent.Config{Server: server, NodeID: resp.NodeID, NodeName: name, AgentToken: resp.AgentToken}
			if err := agent.SaveConfig(p, cfg); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "registered as %s (%s)\n", resp.NodeID, name)
			fmt.Fprintf(cmd.OutOrStdout(), "agent config saved to %s\n", p)
			return nil
		},
	}
	join.Flags().StringVar(&server, "server", "", "control plane URL (e.g. https://x:7777)")
	join.Flags().StringVar(&name, "name", "", "node name")
	join.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read the join token from stdin")
	cmd.AddCommand(join)

	// agent run is added in Task 6.5.

	_ = context.Background() // kept for later commands
	return cmd
}
```

- [ ] **Step 2: Wire into root**

In `internal/cli/root.go`, add:
```go
root.AddCommand(newAgentCmd())
```

- [ ] **Step 3: Compile**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add internal/cli
git commit -m "feat(cli): uncluster agent join --token-stdin"
```

---

### Task 6.4: Agent main loop (heartbeat + cancel-dispatcher)

**Files:**
- Create: `internal/agent/agent.go`
- Create: `internal/agent/cancel.go`

- [ ] **Step 1: Write `cancel.go`**

```go
package agent

import (
	"context"
	"sync"
)

// cancelDispatcher tracks active tasks so cancel signals from the server
// (delivered on heartbeat/chunk responses) can abort the right task's context.
type cancelDispatcher struct {
	mu     sync.Mutex
	active map[string]context.CancelFunc
}

func newCancelDispatcher() *cancelDispatcher {
	return &cancelDispatcher{active: make(map[string]context.CancelFunc)}
}

func (c *cancelDispatcher) Register(taskID string, cancel context.CancelFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active[taskID] = cancel
}

func (c *cancelDispatcher) Unregister(taskID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.active, taskID)
}

func (c *cancelDispatcher) Signal(taskIDs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range taskIDs {
		if fn, ok := c.active[id]; ok {
			fn()
		}
	}
}
```

- [ ] **Step 2: Write `agent.go`**

```go
package agent

import (
	"context"
	"log/slog"
	"time"
)

type Agent struct {
	cfg     Config
	client  *ServerClient
	cancels *cancelDispatcher
	logger  *slog.Logger
}

func New(cfg Config, logger *slog.Logger) *Agent {
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		cfg:     cfg,
		client:  NewServerClient(cfg.Server, cfg.AgentToken),
		cancels: newCancelDispatcher(),
		logger:  logger,
	}
}

// Run blocks until ctx is cancelled or auth fails permanently.
func (a *Agent) Run(ctx context.Context) error {
	hbCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	authErrCh := make(chan error, 2)
	go func() { authErrCh <- a.heartbeatLoop(hbCtx) }()
	go func() { authErrCh <- a.pollLoop(hbCtx) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-authErrCh:
		cancelAll()
		return err
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) error {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	// fire one immediately so registration status is fresh
	if err := a.heartbeatOnce(ctx); err != nil {
		if err == ErrUnauthorized {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := a.heartbeatOnce(ctx); err != nil {
				if err == ErrUnauthorized {
					return err
				}
				a.logger.Warn("heartbeat error", "err", err)
			}
		}
	}
}

func (a *Agent) heartbeatOnce(ctx context.Context) error {
	resp, err := a.client.Heartbeat(ctx, CollectMetrics())
	if err != nil {
		return err
	}
	if len(resp.CancelTaskIDs) > 0 {
		a.cancels.Signal(resp.CancelTaskIDs)
	}
	return nil
}

// pollLoop is completed in Task 6.5 (needs execute.go).
func (a *Agent) pollLoop(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
```

- [ ] **Step 3: Compile**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add internal/agent
git commit -m "feat(agent): main loop + cancelDispatcher + heartbeat goroutine

Heartbeat runs independently of task execution so silent long-running
commands still receive cancel signals within 10s (spec §7.3/§7.4)."
```

---

### Task 6.5: `uncluster agent run`

**Files:**
- Modify: `internal/cli/agent_cmd.go`

- [ ] **Step 1: Append `run` subcommand**

Inside `newAgentCmd`, before `return cmd`:

```go
	run := &cobra.Command{
		Use:   "run",
		Short: "Run the agent in the foreground (used by service units)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := agent.DefaultConfigPath()
			if err != nil {
				return err
			}
			cfg, err := agent.LoadConfig(p)
			if err != nil {
				return fmt.Errorf("load agent config: %w", err)
			}
			if cfg.Server == "" || cfg.AgentToken == "" {
				return fmt.Errorf("agent not joined; run `uncluster agent join` first")
			}
			a := agent.New(cfg, nil)
			return a.Run(cmd.Context())
		},
	}
	cmd.AddCommand(run)
```

- [ ] **Step 2: Compile and commit**

```bash
go build ./...
git add internal/cli
git commit -m "feat(cli): uncluster agent run"
```

---

**SP2 reached:** Operator can run `uncluster server start`, bootstrap a CLI token, mint a join token, `uncluster agent join`, `uncluster agent run`, and see the node in `uncluster nodes ls`. Manual smoke test:

```bash
./uncluster server bootstrap --db /tmp/u.db                        # print CLI token
./uncluster server start --addr :17777 --db /tmp/u.db &
./uncluster config set server=http://localhost:17777
pbpaste | ./uncluster config set token --stdin
./uncluster server token create --kind=join --label=lappy          # print join token
pbpaste | ./uncluster agent join --server=http://localhost:17777 --name=lappy --token-stdin
./uncluster agent run &
sleep 12
./uncluster nodes ls                                               # should show "lappy"
```

---

## Phase 7: Tasks create, dispatcher, long-poll next-task

### Task 7.1: In-process Dispatcher implementation

**Files:**
- Modify: `internal/server/dispatcher.go`
- Create: `internal/server/dispatcher_test.go`

- [ ] **Step 1: Write test**

```go
package server

import (
	"context"
	"testing"
	"time"
)

func TestDispatcher_WaitReturnsOnNotify(t *testing.T) {
	d := newInProcessDispatcher()
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		d.Wait(ctx, "node_a", 2*time.Second)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	d.Notify("node_a")
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Wait did not return after Notify")
	}
}

func TestDispatcher_WaitTimeout(t *testing.T) {
	d := newInProcessDispatcher()
	start := time.Now()
	d.Wait(context.Background(), "node_a", 50*time.Millisecond)
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("Wait returned too early")
	}
}

func TestDispatcher_PublishSubscribe(t *testing.T) {
	d := newInProcessDispatcher()
	ch, unsub := d.Subscribe("task_1")
	defer unsub()
	go d.PublishChunk("task_1", DispatcherEvent{Kind: "chunk", Payload: []byte("hi")})
	select {
	case ev := <-ch:
		if ev.Kind != "chunk" {
			t.Fatalf("kind: %s", ev.Kind)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("no event received")
	}
}
```

- [ ] **Step 2: Flesh out `internal/server/dispatcher.go`**

Replace the earlier stub with:

```go
package server

import (
	"context"
	"sync"
	"time"
)

type DispatcherEvent struct {
	Kind    string // "chunk" | "status" | "done"
	Payload any
}

type inProcessDispatcher struct {
	mu          sync.Mutex
	wakeups     map[string]chan struct{}         // node_id -> wake channel
	subscribers map[string][]chan DispatcherEvent // task_id -> subscriber channels
}

func newInProcessDispatcher() *inProcessDispatcher {
	return &inProcessDispatcher{
		wakeups:     make(map[string]chan struct{}),
		subscribers: make(map[string][]chan DispatcherEvent),
	}
}

func (d *inProcessDispatcher) wakeChan(nodeID string) chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	ch, ok := d.wakeups[nodeID]
	if !ok {
		ch = make(chan struct{}, 1) // buffered 1 — coalesces bursts
		d.wakeups[nodeID] = ch
	}
	return ch
}

func (d *inProcessDispatcher) Notify(nodeID string) {
	ch := d.wakeChan(nodeID)
	select {
	case ch <- struct{}{}:
	default: // already pending
	}
}

func (d *inProcessDispatcher) Wait(ctx context.Context, nodeID string, timeout time.Duration) {
	ch := d.wakeChan(nodeID)
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	case <-ctx.Done():
	}
}

func (d *inProcessDispatcher) Subscribe(taskID string) (<-chan DispatcherEvent, func()) {
	d.mu.Lock()
	ch := make(chan DispatcherEvent, 64)
	d.subscribers[taskID] = append(d.subscribers[taskID], ch)
	d.mu.Unlock()
	return ch, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		subs := d.subscribers[taskID]
		for i, c := range subs {
			if c == ch {
				d.subscribers[taskID] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		close(ch)
	}
}

func (d *inProcessDispatcher) PublishChunk(taskID string, ev DispatcherEvent) {
	d.mu.Lock()
	subs := append([]chan DispatcherEvent(nil), d.subscribers[taskID]...)
	d.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default: // slow subscriber — drop rather than stall
		}
	}
}
```

- [ ] **Step 3: Run tests and commit**

```bash
go test ./internal/server/... -race -v
git add internal/server
git commit -m "feat(server): in-process dispatcher — coalescing wakeups + per-task subscribers"
```

---

### Task 7.2: Tasks handlers — create, long-poll next-task, get

**Files:**
- Create: `internal/server/handlers_tasks.go`
- Modify: `internal/server/router.go`

- [ ] **Step 1: Write `handlers_tasks.go`**

```go
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
)

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var req api.CreateTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Node == "" || req.Command == "" {
		writeError(w, http.StatusBadRequest, "node and command required")
		return
	}
	node, err := s.cfg.Store.GetNode(r.Context(), req.Node)
	if err != nil {
		node, err = s.cfg.Store.GetNodeByName(r.Context(), req.Node)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if node.Status == store.NodeRevoked {
		writeError(w, http.StatusBadRequest, "node is revoked")
		return
	}
	tok := r.Context().Value(ctxAuthedToken).(store.Token)
	task, err := s.cfg.Store.CreateTask(r.Context(), node.ID, req.Command, tok.ID, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.dispatcher.Notify(node.ID)
	writeJSON(w, http.StatusCreated, api.CreateTaskResponse{TaskID: task.ID})
}

func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.cfg.Store.GetTask(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDetail(t))
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := store.TaskStatus(q.Get("status"))
	nodeID := q.Get("node")
	rows, err := s.cfg.Store.ListTasks(r.Context(), nodeID, status, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]api.TaskDetail, 0, len(rows))
	for _, t := range rows {
		out = append(out, toDetail(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func toDetail(t store.Task) api.TaskDetail {
	return api.TaskDetail{
		ID: t.ID, NodeID: t.NodeID, Command: t.Command, Status: string(t.Status),
		ExitCode: t.ExitCode, CreatedAt: t.CreatedAt.Unix(),
		StartedAt: api.TimePtr(t.StartedAt), FinishedAt: api.TimePtr(t.FinishedAt),
		OutputBytes: t.OutputBytes, OutputTruncated: t.OutputTruncated,
	}
}

// --- agent long-poll ---

func (s *Server) handleAgentNextTask(w http.ResponseWriter, r *http.Request) {
	node := r.Context().Value(ctxAuthedNode).(store.Node)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	for {
		task, err := s.cfg.Store.ClaimNextPending(ctx, node.ID, time.Now())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if task != nil {
			writeJSON(w, http.StatusOK, api.NextTaskResponse{TaskID: task.ID, Command: task.Command})
			return
		}
		// Nothing pending — park on the dispatcher until notify or timeout.
		s.dispatcher.Wait(ctx, node.ID, time.Until(deadline(ctx)))
		if ctx.Err() != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Loop: wake-up could be spurious (e.g., race with another agent claim).
	}
}

func deadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(30 * time.Second)
}
```

- [ ] **Step 2: Mount routes**

In `router.go`, inside `/v1`:

```go
		v1.Group(func(cli chi.Router) {
			cli.Use(s.requireAuth(store.TokenCLI))
			cli.Post("/tasks", s.handleCreateTask)
			cli.Get("/tasks", s.handleListTasks)
			cli.Get("/tasks/{id}", s.handleGetTask)
		})
		v1.Group(func(agent chi.Router) {
			agent.Use(s.requireAuth(store.TokenAgent))
			agent.Get("/agent/next-task", s.handleAgentNextTask)
		})
```

- [ ] **Step 3: Test manually**

Run:
```bash
go test ./... -race
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/server
git commit -m "feat(server): POST /v1/tasks, GET /v1/tasks, GET /v1/agent/next-task (long-poll)"
```

---

### Task 7.3: OpenAPI — tasks endpoints

**Files:**
- Modify: `api/openapi.yaml`

- [ ] **Step 1: Append**

```yaml
  /v1/tasks:
    post:
      summary: Create a task for a node
      security: [{ bearerAuth: [] }]
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/CreateTaskRequest" }
      responses:
        "201":
          content:
            application/json:
              schema: { $ref: "#/components/schemas/CreateTaskResponse" }
    get:
      summary: List recent tasks
      security: [{ bearerAuth: [] }]
      parameters:
        - { in: query, name: node, schema: { type: string } }
        - { in: query, name: status, schema: { type: string } }
        - { in: query, name: limit, schema: { type: integer } }
      responses:
        "200":
          content:
            application/json:
              schema:
                type: array
                items: { $ref: "#/components/schemas/TaskDetail" }

  /v1/tasks/{id}:
    get:
      summary: Get task details
      security: [{ bearerAuth: [] }]
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
      responses:
        "200":
          content:
            application/json:
              schema: { $ref: "#/components/schemas/TaskDetail" }
        "404": { description: not found }

  /v1/agent/next-task:
    get:
      summary: Long-poll for the next task assigned to this agent (30s)
      security: [{ bearerAuth: [] }]
      responses:
        "200":
          content:
            application/json:
              schema: { $ref: "#/components/schemas/NextTaskResponse" }
        "204": { description: no task within timeout }
```

And under `components.schemas:`:

```yaml
    CreateTaskRequest:
      type: object
      required: [node, command]
      properties:
        node: { type: string, description: "node id or name" }
        command: { type: string }
    CreateTaskResponse:
      type: object
      properties: { task_id: { type: string } }
    NextTaskResponse:
      type: object
      properties:
        task_id: { type: string }
        command: { type: string }
    TaskDetail:
      type: object
      properties:
        id: { type: string }
        node_id: { type: string }
        command: { type: string }
        status: { type: string }
        exit_code: { type: integer, nullable: true }
        created_at: { type: integer, format: int64 }
        started_at: { type: integer, format: int64, nullable: true }
        finished_at: { type: integer, format: int64, nullable: true }
        output_bytes: { type: integer, format: int64 }
        output_truncated: { type: boolean }
```

- [ ] **Step 2: Commit**

```bash
git add api/openapi.yaml
git commit -m "docs(api): tasks endpoints in openapi.yaml"
```

---

## Phase 8: Task execution on agent + chunk upload + complete

### Task 8.1: Agent `execute.go` — run command, stream pipes, handle cancel

**Files:**
- Create: `internal/agent/execute.go`

- [ ] **Step 1: Write `execute.go`**

```go
package agent

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// executeTask runs a shell command and streams stdout/stderr back via chunk
// POSTs. Cancellation is driven by the Agent.cancels dispatcher (taskCtx).
func (a *Agent) executeTask(parent context.Context, taskID, command string) int {
	taskCtx, cancel := context.WithCancel(parent)
	a.cancels.Register(taskID, cancel)
	defer a.cancels.Unregister(taskID)

	cmd := exec.Command("bash", "-lc", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		a.logger.Warn("start failed", "task", taskID, "err", err)
		return -1
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.streamPipe(taskCtx, taskID, "stdout", stdout) }()
	go func() { defer wg.Done(); a.streamPipe(taskCtx, taskID, "stderr", stderr) }()

	// Kill handler: when taskCtx is cancelled, send SIGTERM to the group;
	// after 5s, SIGKILL.
	killDone := make(chan struct{})
	go func() {
		<-taskCtx.Done()
		if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		}
		select {
		case <-time.After(5 * time.Second):
			if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			}
		case <-killDone:
		}
	}()

	err := cmd.Wait()
	close(killDone)
	wg.Wait()

	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	if taskCtx.Err() != nil {
		return 143 // conventional "killed by SIGTERM" code when nothing better
	}
	return -1
}

// streamPipe reads a pipe line-by-line with periodic flushes, POSTing chunks
// to the server. Flush triggers: 4 KiB buffer, 200 ms idle, or EOF.
func (a *Agent) streamPipe(ctx context.Context, taskID, stream string, r io.Reader) {
	buf := make([]byte, 0, 4096)
	flushTicker := time.NewTicker(200 * time.Millisecond)
	defer flushTicker.Stop()

	br := bufio.NewReader(r)
	readCh := make(chan []byte, 8)
	readDone := make(chan struct{})

	go func() {
		defer close(readDone)
		tmp := make([]byte, 1024)
		for {
			n, err := br.Read(tmp)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, tmp[:n])
				select {
				case readCh <- chunk:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		resp, err := a.client.UploadChunk(ctx, taskID, stream, buf)
		buf = buf[:0]
		if err != nil {
			a.logger.Warn("chunk upload failed", "err", err)
			return
		}
		if resp.Truncated {
			// Server says stop flushing — drain reader but drop.
			buf = nil
		}
		if len(resp.CancelTaskIDs) > 0 {
			a.cancels.Signal(resp.CancelTaskIDs)
		}
	}

	for {
		select {
		case b := <-readCh:
			if buf != nil {
				buf = append(buf, b...)
				if len(buf) >= 4096 {
					flush()
				}
			}
		case <-flushTicker.C:
			flush()
		case <-readDone:
			flush()
			return
		case <-ctx.Done():
			flush()
			return
		}
	}
}
```

- [ ] **Step 2: Implement `pollLoop` for real**

Replace the stub in `internal/agent/agent.go`:

```go
func (a *Agent) pollLoop(ctx context.Context) error {
	backoff := time.Second
	for ctx.Err() == nil {
		task, err := a.client.NextTask(ctx)
		if err == ErrUnauthorized {
			return err
		}
		if err != nil {
			a.logger.Warn("next-task error", "err", err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if task == nil {
			continue // 204 → reconnect
		}
		exitCode := a.executeTask(ctx, task.TaskID, task.Command)
		if err := a.client.Complete(ctx, task.TaskID, exitCode); err != nil {
			if err == ErrUnauthorized {
				return err
			}
			a.logger.Warn("complete failed", "err", err)
		}
	}
	return nil
}
```

- [ ] **Step 3: Compile**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add internal/agent
git commit -m "feat(agent): execute shell commands with stdout/stderr streaming + SIGTERM/SIGKILL on cancel

Process-group kill (Setpgid+Kill(-pgid)) ensures bash subchildren die
too. Chunk flush policy: 4KiB buffer, 200ms idle, or EOF."
```

---

### Task 8.2: Server — chunk upload + complete handlers

**Files:**
- Modify: `internal/server/handlers_agent.go`
- Modify: `internal/server/router.go`

- [ ] **Step 1: Add handlers**

Append to `handlers_agent.go`:

```go
func (s *Server) handleAgentChunks(w http.ResponseWriter, r *http.Request) {
	node := r.Context().Value(ctxAuthedNode).(store.Node)
	taskID := chi.URLParam(r, "id")

	task, err := s.cfg.Store.GetTask(r.Context(), taskID)
	if err != nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if task.NodeID != node.ID {
		writeError(w, http.StatusForbidden, "task belongs to different node")
		return
	}

	var req api.ChunkUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Stream != "stdout" && req.Stream != "stderr" {
		writeError(w, http.StatusBadRequest, "stream must be stdout or stderr")
		return
	}

	res, err := s.cfg.Store.AppendChunk(r.Context(), taskID, req.Stream, req.Data, time.Now(), s.cfg.OutputCapBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Fan out to any SSE subscribers.
	s.dispatcher.PublishChunk(taskID, DispatcherEvent{
		Kind:    "chunk",
		Payload: api.ChunkOut{Stream: req.Stream, Data: req.Data, CreatedAt: time.Now().Unix()},
	})

	cancels, _ := s.cfg.Store.PendingCancelsForNode(r.Context(), node.ID)
	writeJSON(w, http.StatusOK, api.ChunkUploadResponse{
		Truncated: res.Truncated, CancelTaskIDs: cancels,
	})
}

func (s *Server) handleAgentComplete(w http.ResponseWriter, r *http.Request) {
	node := r.Context().Value(ctxAuthedNode).(store.Node)
	taskID := chi.URLParam(r, "id")

	task, err := s.cfg.Store.GetTask(r.Context(), taskID)
	if err != nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if task.NodeID != node.ID {
		writeError(w, http.StatusForbidden, "task belongs to different node")
		return
	}

	var req api.CompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.cfg.Store.CompleteTask(r.Context(), taskID, req.ExitCode, time.Now()); err != nil {
		if err == store.ErrTaskCompleted {
			writeError(w, http.StatusConflict, "already completed")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	final, _ := s.cfg.Store.GetTask(r.Context(), taskID)
	s.dispatcher.PublishChunk(taskID, DispatcherEvent{
		Kind:    "done",
		Payload: map[string]any{"exit_code": final.ExitCode, "status": string(final.Status)},
	})
	w.WriteHeader(http.StatusNoContent)
}
```

Add import `"github.com/go-chi/chi/v5"` if not present.

- [ ] **Step 2: Mount routes**

In `router.go`, in the agent group:

```go
			agent.Post("/agent/tasks/{id}/chunks", s.handleAgentChunks)
			agent.Post("/agent/tasks/{id}/complete", s.handleAgentComplete)
```

- [ ] **Step 3: Append to openapi.yaml**

```yaml
  /v1/agent/tasks/{id}/chunks:
    post:
      summary: Upload a stdout/stderr chunk
      security: [{ bearerAuth: [] }]
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/ChunkUploadRequest" }
      responses:
        "200":
          content:
            application/json:
              schema: { $ref: "#/components/schemas/ChunkUploadResponse" }

  /v1/agent/tasks/{id}/complete:
    post:
      summary: Mark a task complete with an exit code
      security: [{ bearerAuth: [] }]
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/CompleteRequest" }
      responses:
        "204": { description: ok }
        "409": { description: already completed }
```

And schemas:

```yaml
    ChunkUploadRequest:
      type: object
      required: [stream]
      properties:
        stream: { type: string, enum: [stdout, stderr] }
        data: { type: string, format: byte }
    ChunkUploadResponse:
      type: object
      properties:
        truncated: { type: boolean }
        cancel_task_ids:
          type: array
          items: { type: string }
    CompleteRequest:
      type: object
      required: [exit_code]
      properties:
        exit_code: { type: integer }
```

- [ ] **Step 4: Run tests and commit**

```bash
go test ./... -race
git add internal/server api/openapi.yaml
git commit -m "feat(server): agent chunk upload + complete

Chunk upload publishes a DispatcherEvent for SSE subscribers and
returns pending cancels for this node as a piggyback (spec §7.4)."
```

---

## Phase 9: SSE stream + `uncluster run` + `uncluster tasks tail`

### Task 9.1: SSE handler

**Files:**
- Create: `internal/server/sse.go`
- Modify: `internal/server/handlers_tasks.go`
- Modify: `internal/server/router.go`

- [ ] **Step 1: Write `sse.go`**

```go
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// sseWriter helps handlers emit `event: <kind>\ndata: <json>\n\n` frames.
type sseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func newSSE(w http.ResponseWriter) (*sseWriter, bool) {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	return &sseWriter{w: w, flusher: f}, true
}

func (s *sseWriter) Send(kind string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", kind, b); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}
```

- [ ] **Step 2: Add `handleTaskStream` in `handlers_tasks.go`**

```go
func (s *Server) handleTaskStream(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	task, err := s.cfg.Store.GetTask(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	sse, ok := newSSE(w)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Subscribe first to avoid missing events published while we replay.
	ch, unsub := s.dispatcher.Subscribe(id)
	defer unsub()

	// Replay existing chunks (both streams).
	for _, stream := range []string{"stdout", "stderr"} {
		chunks, _ := s.cfg.Store.ListChunks(r.Context(), id, stream, 0, 10000)
		for _, c := range chunks {
			_ = sse.Send("chunk", api.ChunkOut{
				Stream: c.Stream, Seq: c.Seq, Data: c.Data, CreatedAt: c.CreatedAt.Unix(),
			})
		}
	}

	// If task is already terminal, send done and exit.
	if task.Status == store.TaskSucceeded || task.Status == store.TaskFailed || task.Status == store.TaskCancelled {
		_ = sse.Send("done", map[string]any{"exit_code": task.ExitCode, "status": string(task.Status)})
		return
	}

	// Stream live events until ctx done or terminal.
	for {
		select {
		case ev, open := <-ch:
			if !open {
				return
			}
			switch ev.Kind {
			case "chunk":
				_ = sse.Send("chunk", ev.Payload)
			case "done":
				_ = sse.Send("done", ev.Payload)
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}
```

- [ ] **Step 3: Mount route**

In `router.go`, in the CLI group:

```go
			cli.Get("/tasks/{id}/stream", s.handleTaskStream)
```

- [ ] **Step 4: Append to openapi.yaml**

```yaml
  /v1/tasks/{id}/stream:
    get:
      summary: Server-sent events — already-stored chunks replayed, then live, then done
      security: [{ bearerAuth: [] }]
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
      responses:
        "200":
          description: SSE stream (text/event-stream)
```

- [ ] **Step 5: Commit**

```bash
git add internal/server api/openapi.yaml
git commit -m "feat(server): SSE stream for tasks — replay stored chunks, then live, then done"
```

---

### Task 9.2: `uncluster run` + `uncluster tasks tail` CLI

**Files:**
- Create: `internal/cli/run_cmd.go`
- Create: `internal/cli/tasks_cmd.go`
- Create: `internal/cli/sse_client.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Write `sse_client.go`**

```go
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SSEEvent struct {
	Kind string
	Data []byte
}

// StreamSSE calls path and yields events to the callback. Returns when the
// server closes the stream or ctx is cancelled.
func (c *Client) StreamSSE(ctx context.Context, path string, onEvent func(SSEEvent) error) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	// No timeout — stream can be long.
	httpc := &http.Client{Timeout: 0}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("stream: %d", resp.StatusCode)
	}

	br := bufio.NewReader(resp.Body)
	var kind string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "event: "):
			kind = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data := strings.TrimPrefix(line, "data: ")
			if err := onEvent(SSEEvent{Kind: kind, Data: []byte(data)}); err != nil {
				return err
			}
			kind = ""
		case line == "":
			// frame boundary — no-op
		}
		_ = time.Millisecond // avoid unused-import for time
	}

	// json import pre-used to keep it in the imports list
	_ = json.Marshal
}
```

- [ ] **Step 2: Write `run_cmd.go`**

```go
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newRunCmd() *cobra.Command {
	var async bool
	cmd := &cobra.Command{
		Use:   "run <node> -- <cmd>...",
		Short: "Run a shell command on a node",
		Args:  cobra.MinimumNArgs(2),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("CLI not configured; see `uncluster config`")
			}

			// Convention: `uncluster run NODE -- cmd args...`
			// cobra strips the "--"; find the split.
			node := args[0]
			cmdArgs := args[1:]
			command := strings.Join(cmdArgs, " ")

			client := NewClient(cfg.Server, cfg.Token)

			var created api.CreateTaskResponse
			if err := client.Do(cmd.Context(), "POST", "/v1/tasks",
				api.CreateTaskRequest{Node: node, Command: command}, &created); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[%s on %s]\n", created.TaskID, node)

			if async {
				fmt.Fprintln(cmd.OutOrStdout(), created.TaskID)
				return nil
			}
			return tailTask(cmd.Context(), client, created.TaskID)
		},
	}
	cmd.Flags().BoolVar(&async, "async", false, "print task id and return; don't tail")
	return cmd
}

// tailTask attaches to /stream and prints chunks until done.
// Returns an error whose ExitCode (if any) is propagated by the caller.
func tailTask(ctx context.Context, c *Client, taskID string) error {
	var finalExit *int
	err := c.StreamSSE(ctx, "/v1/tasks/"+taskID+"/stream", func(ev SSEEvent) error {
		switch ev.Kind {
		case "chunk":
			var out api.ChunkOut
			_ = json.Unmarshal(ev.Data, &out)
			if out.Stream == "stderr" {
				os.Stderr.Write(out.Data)
			} else {
				os.Stdout.Write(out.Data)
			}
		case "done":
			var d struct {
				ExitCode *int   `json:"exit_code"`
				Status   string `json:"status"`
			}
			_ = json.Unmarshal(ev.Data, &d)
			finalExit = d.ExitCode
			return io.EOF
		}
		return nil
	})
	if err != nil && err != io.EOF {
		return err
	}
	if finalExit != nil && *finalExit != 0 {
		os.Exit(*finalExit)
	}
	return nil
}
```

Add imports: `"context"`, `"io"`.

- [ ] **Step 3: Write `tasks_cmd.go`**

```go
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newTasksCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "tasks", Short: "Inspect tasks"}

	cmd.AddCommand(&cobra.Command{
		Use:   "tail <id>",
		Short: "Tail a task's output (SSE)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			return tailTask(c.Context(), client, args[0])
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show <id>",
		Short: "Show task details",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			var t api.TaskDetail
			if err := client.Do(c.Context(), "GET", "/v1/tasks/"+args[0], nil, &t); err != nil {
				return err
			}
			b, _ := json.MarshalIndent(t, "", "  ")
			fmt.Fprintln(c.OutOrStdout(), string(b))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List recent tasks",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			var out []api.TaskDetail
			if err := client.Do(c.Context(), "GET", "/v1/tasks", nil, &out); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "%-28s %-12s %s\n", "ID", "STATUS", "COMMAND")
			for _, t := range out {
				fmt.Fprintf(c.OutOrStdout(), "%-28s %-12s %s\n", t.ID, t.Status, t.Command)
			}
			return nil
		},
	})

	_ = context.Background()
	_ = io.EOF
	_ = os.Stdout
	return cmd
}
```

- [ ] **Step 4: Wire into root**

```go
root.AddCommand(newRunCmd())
root.AddCommand(newTasksCmd())
```

- [ ] **Step 5: Compile and commit**

```bash
go build ./...
git add internal/cli
git commit -m "feat(cli): uncluster run + uncluster tasks {tail,show,ls}"
```

---

**SP3 reached:** `uncluster run <node> -- <cmd>` works end-to-end. Full MVP is functional. Smoke test:

```bash
./uncluster run lappy -- 'echo hello from $(hostname)'
./uncluster run lappy -- 'sleep 2; ls /tmp'
./uncluster tasks ls
```

---

## Phase 10: Cancellation end-to-end

### Task 10.1: Cancel handler + CLI command

**Files:**
- Modify: `internal/server/handlers_tasks.go`
- Modify: `internal/server/router.go`
- Modify: `internal/cli/tasks_cmd.go`
- Modify: `api/openapi.yaml`

- [ ] **Step 1: Add server handler**

Append to `handlers_tasks.go`:

```go
func (s *Server) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	task, err := s.cfg.Store.GetTask(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	switch task.Status {
	case store.TaskPending:
		if err := s.cfg.Store.MarkTaskCancelled(r.Context(), id, time.Now()); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.dispatcher.PublishChunk(id, DispatcherEvent{
			Kind: "done", Payload: map[string]any{"exit_code": nil, "status": "cancelled"},
		})
	case store.TaskRunning:
		if err := s.cfg.Store.MarkTaskCancelling(r.Context(), id); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		// Wake the node's agent so its next heartbeat/chunk response picks up
		// the cancel list faster than the 10s tick.
		s.dispatcher.Notify(task.NodeID)
	default:
		writeError(w, http.StatusConflict, "task is not cancellable in its current state")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
```

- [ ] **Step 2: Mount**

In `router.go` CLI group:
```go
			cli.Post("/tasks/{id}/cancel", s.handleCancelTask)
```

- [ ] **Step 3: Add `uncluster tasks cancel` CLI**

In `tasks_cmd.go`:
```go
	cmd.AddCommand(&cobra.Command{
		Use:   "cancel <id>",
		Short: "Cancel a pending or running task",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			return client.Do(c.Context(), "POST", "/v1/tasks/"+args[0]+"/cancel", nil, nil)
		},
	})
```

- [ ] **Step 4: Append to openapi.yaml**

```yaml
  /v1/tasks/{id}/cancel:
    post:
      summary: Cancel a pending or running task
      security: [{ bearerAuth: [] }]
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
      responses:
        "202": { description: cancellation requested }
        "404": { description: not found }
        "409": { description: not cancellable in current state }
```

- [ ] **Step 5: Test manually**

```bash
./uncluster run lappy -- 'sleep 300' &
sleep 1
TASK=$(./uncluster tasks ls | awk 'NR==2 {print $1}')
./uncluster tasks cancel "$TASK"
./uncluster tasks show "$TASK"
```

Expected: status becomes `cancelled` within ~10s.

- [ ] **Step 6: Commit**

```bash
git add internal/server internal/cli api/openapi.yaml
git commit -m "feat: task cancellation (POST /v1/tasks/{id}/cancel + CLI)

pending → cancelled directly; running → cancelling (agent picks up via
heartbeat response or next chunk POST response per spec §7.4)."
```

---

### Task 10.2: Handle Ctrl-C on `uncluster run` → cancel the task

**Files:**
- Modify: `internal/cli/run_cmd.go`

- [ ] **Step 1: Capture signals in `uncluster run`**

Wrap `tailTask` in a signal-aware ctx: add to `newRunCmd`'s `RunE` before calling `tailTask`:

```go
			runCtx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			go func() {
				<-runCtx.Done()
				// Best-effort cancel on interrupt — don't block exit.
				ctxCancel, cancelCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancelCancel()
				_ = client.Do(ctxCancel, "POST", "/v1/tasks/"+created.TaskID+"/cancel", nil, nil)
			}()

			return tailTask(runCtx, client, created.TaskID)
```

Add imports: `"context"`, `"os/signal"`, `"syscall"`, `"time"`.

- [ ] **Step 2: Commit**

```bash
git add internal/cli
git commit -m "feat(cli): Ctrl-C on uncluster run sends task cancel before exit"
```

---

## Phase 11: Revocation end-to-end + `uncluster nodes`

### Task 11.1: `uncluster nodes {ls,show,rm}` CLI

**Files:**
- Create: `internal/cli/nodes_cmd.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Write `nodes_cmd.go`**

```go
package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/derek-x-wang/uncluster/internal/api"
)

func newNodesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "nodes", Short: "Inspect nodes"}

	cmd.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List registered nodes",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			var out []api.NodeSummary
			if err := client.Do(c.Context(), "GET", "/v1/nodes", nil, &out); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "%-18s %-10s %-10s %s\n", "NAME", "STATUS", "SEEN", "OS")
			for _, n := range out {
				seen := "never"
				if n.LastSeenAt != nil {
					seen = fmt.Sprintf("%ds ago", time.Now().Unix()-*n.LastSeenAt)
				}
				os := ""
				if v, ok := n.Metadata["os"].(string); ok {
					os = v
				}
				fmt.Fprintf(c.OutOrStdout(), "%-18s %-10s %-10s %s\n", n.Name, n.Status, seen, os)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show <name|id>",
		Short: "Show a single node with full metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			var n api.NodeSummary
			if err := client.Do(c.Context(), "GET", "/v1/nodes/"+args[0], nil, &n); err != nil {
				return err
			}
			b, _ := json.MarshalIndent(n, "", "  ")
			fmt.Fprintln(c.OutOrStdout(), string(b))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "rm <name|id>",
		Short: "Revoke a node (its agent token is revoked, name is freed for reuse)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			cfg, _ := LoadCLIConfig()
			client := NewClient(cfg.Server, cfg.Token)
			return client.Do(c.Context(), "DELETE", "/v1/nodes/"+args[0], nil, nil)
		},
	})
	return cmd
}
```

- [ ] **Step 2: Wire into root**

```go
root.AddCommand(newNodesCmd())
```

- [ ] **Step 3: Compile and commit**

```bash
go build ./...
git add internal/cli
git commit -m "feat(cli): uncluster nodes {ls,show,rm}"
```

---

### Task 11.2: Agent exits cleanly on 401 after revocation

**Files:**
- Modify: `internal/agent/agent.go`

- [ ] **Step 1: Verify existing behavior**

`heartbeatLoop` and `pollLoop` already return `ErrUnauthorized` when the server responds 401 (see Task 6.2 `do` helper), and `Run` returns that error. Verify the CLI surfaces it:

Modify the agent `run` subcommand in `internal/cli/agent_cmd.go` (inside `RunE`):

```go
			if err := a.Run(cmd.Context()); err != nil {
				// Known-good terminal state: revoked token → exit 0, printing a note.
				if errors.Is(err, agent.ErrUnauthorized) {
					fmt.Fprintln(cmd.ErrOrStderr(), "agent: revoked by server; exiting")
					return nil
				}
				return err
			}
			return nil
```

Add `"errors"` import.

- [ ] **Step 2: Commit**

```bash
git add internal/cli
git commit -m "feat(agent): exit cleanly with a friendly message on 401 after revocation"
```

---

## Phase 12: Reaper + robustness

### Task 12.1: Background reaper for stale running tasks

**Files:**
- Create: `internal/server/reaper.go`
- Modify: `internal/server/server.go`

- [ ] **Step 1: Write `reaper.go`**

```go
package server

import (
	"context"
	"time"

	"github.com/derek-x-wang/uncluster/internal/store"
)

// runReaper periodically fails tasks whose node hasn't heartbeat'd in >60s.
func (s *Server) runReaper(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cutoff := now.Add(-60 * time.Second)
			stale, err := s.cfg.Store.FindStaleRunning(ctx, cutoff)
			if err != nil {
				s.cfg.Logger.Warn("reaper: FindStaleRunning failed", "err", err)
				continue
			}
			for _, task := range stale {
				marker := []byte("\n[uncluster: agent lost, task reaped at " + now.UTC().Format(time.RFC3339) + "]\n")
				_, _ = s.cfg.Store.AppendChunk(ctx, task.ID, "stderr", marker, now, s.cfg.OutputCapBytes)
				if err := s.cfg.Store.MarkTaskFailedLost(ctx, task.ID, now); err != nil {
					s.cfg.Logger.Warn("reaper: mark failed", "task", task.ID, "err", err)
					continue
				}
				s.dispatcher.PublishChunk(task.ID, DispatcherEvent{
					Kind: "done", Payload: map[string]any{"exit_code": -1, "status": string(store.TaskFailed)},
				})
			}
		}
	}
}
```

- [ ] **Step 2: Launch reaper from `Server.Start`**

In `internal/server/server.go`, inside `Start`, after `s.cfg.Logger.Info(...)` and before `hs.ListenAndServe()`:

```go
	go s.runReaper(ctx)
```

- [ ] **Step 3: Compile and commit**

```bash
go build ./...
git add internal/server
git commit -m "feat(server): reaper — fails running tasks after 60s of no heartbeat

Appends an [agent lost] stderr marker and publishes a 'done' event so
any SSE tailers see the state transition immediately (spec §7.5)."
```

---

## Phase 13: Agent service install (nice-to-have)

### Task 13.1: `uncluster agent install|uninstall`

**Files:**
- Modify: `internal/cli/agent_cmd.go`

- [ ] **Step 1: Add subcommands**

Append inside `newAgentCmd`:

```go
	install := &cobra.Command{
		Use:   "install",
		Short: "Install the agent as a user service (launchd on macOS, systemd user on Linux)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return svcAction("install")
		},
	}
	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the agent service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return svcAction("uninstall")
		},
	}
	cmd.AddCommand(install, uninstall)
```

Add a helper at the bottom of the file:

```go
func svcAction(action string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	svcCfg := &service.Config{
		Name:        "com.uncluster.agent",
		DisplayName: "Uncluster Agent",
		Description: "Uncluster node agent",
		Executable:  exe,
		Arguments:   []string{"agent", "run"},
		Option:      map[string]interface{}{"UserService": true},
	}
	prg := &agentService{}
	s, err := service.New(prg, svcCfg)
	if err != nil {
		return err
	}
	return service.Control(s, action)
}

type agentService struct{}

func (a *agentService) Start(service.Service) error { return nil }
func (a *agentService) Stop(service.Service) error  { return nil }
```

Add imports:
```go
"os"
"github.com/kardianos/service"
```

- [ ] **Step 2: Smoke test on macOS**

```bash
./uncluster agent install
launchctl list | grep uncluster
./uncluster agent uninstall
```

- [ ] **Step 3: Commit**

```bash
git add internal/cli
git commit -m "feat(cli): uncluster agent {install,uninstall} via kardianos/service"
```

---

## Phase 14: Integration tests, CI, cross-compile, OpenAPI drift

### Task 14.1: End-to-end integration test

**Files:**
- Create: `internal/server/integration_test.go`

This test exercises the happy path in-process: server + agent + creating a task via the HTTP API + asserting streamed output.

- [ ] **Step 1: Write test**

```go
package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/agent"
	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
	"github.com/derek-x-wang/uncluster/internal/token"
)

func TestEndToEnd_RunCommand(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := server.New(server.Config{Store: st})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Mint CLI token directly.
	cliTok, _ := token.Generate(token.KindCLI)
	cliHash, _ := token.HashSecret(cliTok.Secret)
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		cliTok.ID, store.TokenCLI, nil, cliHash, "e2e")

	// Mint join token, register agent.
	jt, _ := token.Generate(token.KindJoin)
	jtHash, _ := token.HashSecret(jt.Secret)
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		jt.ID, store.TokenJoin, nil, jtHash, "e2e-join")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	agentClient := agent.NewServerClient(ts.URL, "")
	reg, err := agentClient.Register(ctx, api.AgentRegisterRequest{
		JoinToken: jt.String(), Name: "e2e-node", Metadata: map[string]any{"os": "test"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Spin up agent in a goroutine.
	a := agent.New(agent.Config{
		Server: ts.URL, NodeID: reg.NodeID, NodeName: "e2e-node", AgentToken: reg.AgentToken,
	}, nil)
	go func() { _ = a.Run(ctx) }()

	// Wait for heartbeat to land.
	time.Sleep(1 * time.Second)

	// Create task via API.
	body, _ := json.Marshal(api.CreateTaskRequest{Node: "e2e-node", Command: `echo hello && echo world`})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cliTok.String())
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("create task: %v status=%d", err, resp.StatusCode)
	}
	var created api.CreateTaskResponse
	_ = json.NewDecoder(resp.Body).Decode(&created)

	// Poll task until terminal.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/tasks/"+created.TaskID, nil)
		req.Header.Set("Authorization", "Bearer "+cliTok.String())
		resp, _ := http.DefaultClient.Do(req)
		var detail api.TaskDetail
		_ = json.NewDecoder(resp.Body).Decode(&detail)
		if detail.Status == "succeeded" {
			// Fetch chunks and check output.
			req, _ := http.NewRequest("GET", ts.URL+"/v1/tasks/"+created.TaskID+"/chunks", nil)
			req.Header.Set("Authorization", "Bearer "+cliTok.String())
			cresp, _ := http.DefaultClient.Do(req)
			b := new(bytes.Buffer)
			_, _ = b.ReadFrom(cresp.Body)
			if !strings.Contains(b.String(), "hello") || !strings.Contains(b.String(), "world") {
				t.Fatalf("output missing expected lines; got: %s", b.String())
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("task did not complete within 10s")
}
```

- [ ] **Step 2: Add chunks GET endpoint (CLI side)**

The test expects `GET /v1/tasks/{id}/chunks`. Add handler in `handlers_tasks.go`:

```go
func (s *Server) handleTaskChunks(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	stream := r.URL.Query().Get("stream") // "" = both
	rows, err := s.cfg.Store.ListChunks(r.Context(), id, stream, 0, 0)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	out := make([]api.ChunkOut, 0, len(rows))
	for _, c := range rows {
		out = append(out, api.ChunkOut{
			Stream: c.Stream, Seq: c.Seq, Data: c.Data, CreatedAt: c.CreatedAt.Unix(),
		})
	}
	writeJSON(w, http.StatusOK, api.ChunksResponse{Chunks: out})
}
```

Mount in `router.go` CLI group:
```go
			cli.Get("/tasks/{id}/chunks", s.handleTaskChunks)
```

Update test's response decode:
```go
			var chunks api.ChunksResponse
			_ = json.NewDecoder(cresp.Body).Decode(&chunks)
			b := new(bytes.Buffer)
			for _, c := range chunks.Chunks {
				b.Write(c.Data)
			}
```

Also append to openapi.yaml.

- [ ] **Step 3: Run test and commit**

```bash
go test ./... -race -v -run TestEndToEnd
git add .
git commit -m "test: end-to-end integration — register, run echo, assert output"
```

---

### Task 14.2: Concurrency, cancellation, and output-cap acceptance tests

**Files:**
- Modify: `internal/server/integration_test.go`

- [ ] **Step 1: Extract a shared e2e harness**

Add a helper at the bottom of `integration_test.go` that the three acceptance tests reuse:

```go
type e2eHarness struct {
	st        store.Store
	srv       *server.Server
	ts        *httptest.Server
	cliToken  string
	agentCtx  context.Context
	agentStop context.CancelFunc
	nodeName  string
	nodeID    string
}

func newHarness(t *testing.T, outputCap int64) *e2eHarness {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{Store: st, OutputCapBytes: outputCap})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	cliTok, _ := token.Generate(token.KindCLI)
	cliHash, _ := token.HashSecret(cliTok.Secret)
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		cliTok.ID, store.TokenCLI, nil, cliHash, "h")

	jt, _ := token.Generate(token.KindJoin)
	jtHash, _ := token.HashSecret(jt.Secret)
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		jt.ID, store.TokenJoin, nil, jtHash, "h-join")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	ac := agent.NewServerClient(ts.URL, "")
	reg, err := ac.Register(ctx, api.AgentRegisterRequest{
		JoinToken: jt.String(), Name: "h-node", Metadata: map[string]any{"os": "test"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	a := agent.New(agent.Config{
		Server: ts.URL, NodeID: reg.NodeID, NodeName: "h-node", AgentToken: reg.AgentToken,
	}, nil)
	agentCtx, agentStop := context.WithCancel(ctx)
	go func() { _ = a.Run(agentCtx) }()
	t.Cleanup(agentStop)

	// Wait for first heartbeat so node.last_seen_at is set.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := st.GetNode(ctx, reg.NodeID)
		if err == nil && n.LastSeenAt != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	return &e2eHarness{
		st: st, srv: srv, ts: ts,
		cliToken: cliTok.String(),
		agentCtx: agentCtx, agentStop: agentStop,
		nodeName: "h-node", nodeID: reg.NodeID,
	}
}

func (h *e2eHarness) createTask(t *testing.T, command string) string {
	t.Helper()
	body, _ := json.Marshal(api.CreateTaskRequest{Node: h.nodeName, Command: command})
	req, _ := http.NewRequest("POST", h.ts.URL+"/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.cliToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("create task: %v status=%d", err, resp.StatusCode)
	}
	var out api.CreateTaskResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.TaskID
}

func (h *e2eHarness) getTask(t *testing.T, id string) api.TaskDetail {
	t.Helper()
	req, _ := http.NewRequest("GET", h.ts.URL+"/v1/tasks/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+h.cliToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out api.TaskDetail
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (h *e2eHarness) cancelTask(t *testing.T, id string) {
	t.Helper()
	req, _ := http.NewRequest("POST", h.ts.URL+"/v1/tasks/"+id+"/cancel", nil)
	req.Header.Set("Authorization", "Bearer "+h.cliToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode >= 400 {
		t.Fatalf("cancel: %v status=%d", err, resp.StatusCode)
	}
}

func (h *e2eHarness) waitStatus(t *testing.T, id, want string, within time.Duration) api.TaskDetail {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		d := h.getTask(t, id)
		if d.Status == want {
			return d
		}
		time.Sleep(100 * time.Millisecond)
	}
	final := h.getTask(t, id)
	t.Fatalf("task %s status=%s, want %s (within %s)", id, final.Status, want, within)
	return final
}
```

- [ ] **Step 2: Add `TestAcceptance_NoDoubleClaim`**

```go
func TestAcceptance_NoDoubleClaim(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := server.New(server.Config{Store: st})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Register node directly (no agent running — we want to control polls).
	n, _ := st.CreateNode(context.Background(), store.NewNodeParams{Name: "c"})
	agentTok, _ := token.Generate(token.KindAgent)
	hash, _ := token.HashSecret(agentTok.Secret)
	nid := n.ID
	_, _ = st.(store.TestInsertHook).InsertTokenWithID(context.Background(),
		agentTok.ID, store.TokenAgent, &nid, hash, "c")

	// Create exactly one pending task.
	_, _ = st.CreateTask(context.Background(), n.ID, "echo only-one", "", time.Now())

	poll := func() int {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/v1/agent/next-task", nil)
		req.Header.Set("Authorization", "Bearer "+agentTok.String())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return -1
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	ch := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() { ch <- poll() }()
	}
	got200, got204 := 0, 0
	for i := 0; i < 2; i++ {
		switch <-ch {
		case 200:
			got200++
		case 204:
			got204++
		}
	}
	if got200 != 1 || got204 != 1 {
		t.Fatalf("expected exactly one claim: 200=%d, 204=%d", got200, got204)
	}
}
```

- [ ] **Step 3: Add `TestAcceptance_SilentCommandCancel`**

```go
func TestAcceptance_SilentCommandCancel(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	h := newHarness(t, 0) // default cap

	// sleep 60 produces no stdout/stderr — forces cancel delivery through heartbeat.
	id := h.createTask(t, "sleep 60")

	// Wait for the task to start (status=running) before cancelling.
	h.waitStatus(t, id, "running", 10*time.Second)

	start := time.Now()
	h.cancelTask(t, id)
	final := h.waitStatus(t, id, "cancelled", 20*time.Second)

	latency := time.Since(start)
	if latency > 15*time.Second {
		t.Fatalf("cancel latency %s exceeds 15s budget (spec acceptance §11 #9)", latency)
	}
	if final.FinishedAt == nil {
		t.Fatal("finished_at should be set on cancelled task")
	}
}
```

Add `"os/exec"` to the test-file imports if not already present.

- [ ] **Step 4: Add `TestAcceptance_OutputCap`**

```go
func TestAcceptance_OutputCap(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	const cap = int64(1024) // 1 KiB — small for fast test
	h := newHarness(t, cap)

	// Emit ~8 KiB so we're well above the cap.
	id := h.createTask(t, `yes | head -c 8192`)

	final := h.waitStatus(t, id, "succeeded", 15*time.Second)
	if !final.OutputTruncated {
		t.Fatalf("expected output_truncated=true; got task: %+v", final)
	}
	// output_bytes = actual trimmed bytes + truncation marker; allow a generous
	// envelope for the marker (the marker is ~45 bytes).
	if final.OutputBytes > cap+256 {
		t.Fatalf("output_bytes %d exceeds cap(%d)+256 marker envelope", final.OutputBytes, cap)
	}
	// The marker must appear in stored output.
	chunks, _ := h.st.ListChunks(context.Background(), id, "stdout", 0, 10000)
	var joined []byte
	for _, c := range chunks {
		joined = append(joined, c.Data...)
	}
	if !bytes.Contains(joined, []byte("output truncated")) {
		t.Fatalf("truncation marker missing from stored stdout")
	}
}
```

- [ ] **Step 5: Run tests and commit**

Run:
```bash
go test ./internal/server/... -race -v -run TestAcceptance
```

Expected: all three PASS.

Commit:
```bash
git add internal/server
git commit -m "test: acceptance §11 #8, #9, #10 — concurrency, silent-cancel, output-cap

Shared e2eHarness wires server+agent in-process. Silent-cancel asserts
cancel latency ≤15s to prove heartbeat delivery works for commands that
produce no output. Output-cap asserts both the flag and the marker."
```

---

### Task 14.3: OpenAPI drift test

**Files:**
- Create: `internal/server/openapi_drift_test.go`

- [ ] **Step 1: Write test**

```go
package server_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/derek-x-wang/uncluster/internal/server"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// TestOpenAPIDrift enforces that every route mounted by the server is present
// in api/openapi.yaml. Satisfies acceptance §11 #13.
func TestOpenAPIDrift(t *testing.T) {
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "d.db"))
	defer st.Close()
	srv := server.New(server.Config{Store: st})

	// Find api/openapi.yaml by walking up from this test's working directory.
	yamlPath := ""
	for _, rel := range []string{"api/openapi.yaml", "../api/openapi.yaml", "../../api/openapi.yaml"} {
		if _, err := os.Stat(rel); err == nil {
			yamlPath = rel
			break
		}
	}
	if yamlPath == "" {
		t.Skip("openapi.yaml not found relative to test")
	}
	y, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(y)

	_ = chi.Walk(srv.Handler().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// Skip middleware-only paths.
		if route == "" || strings.HasPrefix(route, "/healthz") {
			return nil
		}
		if !strings.Contains(yaml, route) {
			t.Errorf("route %s %s not documented in openapi.yaml", method, route)
		}
		return nil
	})
}
```

- [ ] **Step 2: Run and commit**

```bash
go test ./... -race -run TestOpenAPIDrift -v
git add internal/server
git commit -m "test: openapi drift — every mounted route must appear in openapi.yaml"
```

---

### Task 14.4: Cross-compile script

**Files:**
- Create: `scripts/build.sh`

- [ ] **Step 1: Write script**

```bash
#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always --dirty)}"
OUT="${OUT:-dist}"
mkdir -p "$OUT"

LDFLAGS="-s -w -X github.com/derek-x-wang/uncluster/internal/version.Version=${VERSION}"

targets=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
)

for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  bin="uncluster-${os}-${arch}"
  echo "building ${bin} (VERSION=${VERSION})"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${OUT}/${bin}" ./cmd/uncluster
done

echo "done: $(ls -lh "${OUT}")"
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x scripts/build.sh
./scripts/build.sh
ls -lh dist/
git add scripts/build.sh
git commit -m "build: cross-compile script for darwin+linux amd64+arm64"
```

---

### Task 14.5: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write workflow**

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
          cache: true
      - name: go vet
        run: go vet ./...
      - name: go test
        run: go test ./... -race -count=1

  build:
    runs-on: ubuntu-latest
    needs: test
    strategy:
      matrix:
        include:
          - { goos: darwin, goarch: amd64 }
          - { goos: darwin, goarch: arm64 }
          - { goos: linux,  goarch: amd64 }
          - { goos: linux,  goarch: arm64 }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
          cache: true
      - name: build
        env:
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
          CGO_ENABLED: "0"
        run: |
          go build -trimpath -ldflags "-s -w" -o uncluster-${{ matrix.goos }}-${{ matrix.goarch }} ./cmd/uncluster
      - uses: actions/upload-artifact@v4
        with:
          name: uncluster-${{ matrix.goos }}-${{ matrix.goarch }}
          path: uncluster-${{ matrix.goos }}-${{ matrix.goarch }}
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: github actions — vet, test, cross-compile"
```

---

**SP5 reached:** V1 is complete.

Final acceptance check against spec §11:

- [ ] #1 — `uncluster server start` listens on :7777. Verify with `lsof -iTCP:7777`.
- [ ] #2 — CLI can `config set` via `--stdin`, run `nodes ls` with a non-arg token. `ps auxf` shows no token in argv.
- [ ] #3 — `server token create --kind=join` + `agent join` registers a node; `nodes ls` shows it with live metadata.
- [ ] #4 — Kill & restart an agent; it re-appears in `nodes ls` within one heartbeat (~10s).
- [ ] #5 — `uncluster run <node> -- echo hi` streams output and propagates exit code.
- [ ] #6 — `uncluster tasks tail <id>` attaches mid-run and streams remaining output.
- [ ] #7 — `uncluster nodes rm <name>` → agent 401s → rejoin with same name works.
- [ ] #8 — Concurrency test (`TestAcceptance_NoDoubleClaim`) passes.
- [ ] #9 — Silent-cancel test passes (see Task 14.2 implementation note).
- [ ] #10 — Output-cap test passes (see Task 14.2 implementation note).
- [ ] #11 — Integration test covers #1–#7 in CI (`TestEndToEnd_RunCommand`).
- [ ] #12 — CI produces four binaries.
- [ ] #13 — `TestOpenAPIDrift` passes; `api/openapi.yaml` documents every handler route.

---

## Execution notes

- **Ship points are not hard gates.** They mark natural pause points for a human to demo and get feedback; merging can happen at any phase boundary.
- **Each task commits at least once.** If a task's steps span multiple commits, the commit message should still reflect the task's overall intent.
- **Don't skip TDD for "simple" tasks.** Early tasks are TDD-heavy by design; later tasks (where patterns are established) can bundle related tests into one step but still write tests first.
- **If a step's code disagrees with the spec, the spec wins.** If you find a spec issue mid-implementation, stop and raise it; don't silently adjust.
- **OpenAPI YAML must stay in sync.** Every handler-adding task includes an openapi.yaml update. The drift test (Task 14.3) enforces this in CI.

---

## Self-review against the spec

1. **Spec §3 transport (HTTP-only, long-poll + SSE).** Covered by Phase 7 (next-task long-poll) + Phase 9 (SSE). ✓
2. **Spec §4 data model.** Covered by Phase 2. Chunk PK is (task_id, stream, seq). ✓
3. **Spec §5 REST endpoints.** All listed endpoints have handler tasks in Phases 4, 5, 7, 8, 9, 10; openapi.yaml is updated alongside each. ✓
4. **Spec §5.2 CLI surface.** Full CLI matrix covered across Phases 4, 6, 9, 10, 11, 13. ✓
5. **Spec §5.2.1 token input on stdin/env only.** `ReadSecretToken` (Task 6.3) enforces this; `config set` explicitly rejects `token=<value>` on argv (Task 4.2). ✓
6. **Spec §6 registration flow.** Implemented by Tasks 5.1 (server side), 6.3 (agent side), 4.3 (bootstrap first CLI token). ✓
7. **Spec §6.6 token format with indexed ID + argon2(secret).** Implemented by Task 1.1 (generate/parse/hash/verify) + Task 3.3 (middleware does id lookup then verify). ✓
8. **Spec §7.2 atomic claim.** Task 2.5 (`ClaimNextPending` with UPDATE ... RETURNING + status re-check). Test in Task 14.2 (#8). ✓
9. **Spec §7.3 three-goroutine agent model.** Tasks 6.4 + 8.1 + 10.x implement heartbeatLoop, pollLoop, cancelDispatcher, stream pipes. ✓
10. **Spec §7.4 cancellation delivery via heartbeat/chunk response piggyback.** Server side in Task 5.1 (heartbeat), 8.2 (chunks). Agent side in Task 8.1 (stream upload checks response) + Task 6.4 (heartbeat checks response). ✓
11. **Spec §7.5 output cap.** Task 2.6 (store-side) + Task 8.2 (handler passes OutputCapBytes). ✓
12. **Spec §7.6 failure modes.** Reaper in Task 12.1 covers agent-crash + server-crash cases (via 60s stale detection). ✓
13. **Spec §11 acceptance.** Every numbered criterion has a task or acceptance test. Two skipped tests (#9, #10) have explicit implementation notes and are gated from V1-done.

No gaps flagged.




