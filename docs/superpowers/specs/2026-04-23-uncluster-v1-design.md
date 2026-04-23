# Uncluster V1 — Design

**Date:** 2026-04-23
**Status:** Approved (brainstorming phase) — awaiting implementation plan
**Author:** Derek (derek@getbite.com) with Claude

---

## 1. Vision

Uncluster is a lightweight, personal compute layer for people who have multiple machines (old laptops, home servers, workstations) and want to use them together without turning their life into Kubernetes.

> Treat a group of personal machines as a usable pool of compute — without heavy infrastructure, complex orchestration, or rigid systems.

The system is built on one belief: **AI agents don't need a full orchestration platform — they just need a map of the system and a way to act.** We expose structured machine state and minimal execution capability, and let AI (or user logic) decide what to do.

### Personal motivation

The operator has multiple MacBooks (active and old), a home "server" machine, and different environments across locations. Today they SSH into machines manually, have no global resource view, and can't easily decide where to run a task. They do not want Kubernetes, containers-everywhere, or complex setup.

### Philosophy

- **Lightweight over powerful.** No YAML, no DSLs. Feels like a tool, not a platform.
- **Agent is minimal and dumb.** Reports basic state, runs commands, tiny dependency footprint.
- **Control plane is thin.** A coordination layer, not a backend or SaaS.
- **AI-first, not rule-based.** Expose clean data + simple actions; stay out of the way.
- **No cluster complexity.** No containers, no schedulers, no distributed consensus, no overlay networking of its own.

---

## 2. V1 Scope

V1 is the minimum usable version:

1. Multiple nodes can register themselves.
2. Server can list all nodes and their basic stats.
3. A task can be sent to a node and executed.
4. Output is streamed back and the final exit code is returned.

That's it. Anything beyond this list is explicitly V2+ — see §10.

### Key decisions (with brief rationale)

| Decision | Choice | Why |
|---|---|---|
| Networking model | Nodes dial out (HTTP long-poll) | Works behind any NAT, any firewall. Tailscale setup becomes "point agent at tailnet URL." No Uncluster-specific network layer. |
| Task types in V1 | Shell commands only | Covers 90% of real use; typed capabilities and file transfer come later. |
| Output model | Streaming chunks, stored, tail-able or batched | Live-tail for humans, batched fetch for AI/scripts — same backend. |
| Client surfaces | REST API + single CLI binary | AI drives via shell for V1; MCP server is a later additive leaf. |
| Auth | Per-node tokens via one-time join flow; CLI tokens also required | Per-node revocation, no mTLS overhead. |
| Implementation language | Go | Fastest path to V1, excellent CLI/cross-compile story. Interfaces preserve future portability. |
| Persistence | SQLite (pluggable via `Store` interface) | Right tool for single-user, supports future Postgres/DynamoDB/etc. |
| Repo layout | Single repo; future alternative servers (e.g. TS/Workers) live in a subfolder | OpenAPI contract + multiple implementations stay in lockstep. |

### Explicit trade-offs acknowledged

- **Go locks out Cloudflare Workers as a server target in V1.** Accepted; a TypeScript/Hono port for Workers is a future path, made cheap by the OpenAPI contract + `Store`/`Dispatcher` interfaces.
- **Long-poll is hostile to AWS Lambda billing.** Accepted for V1. A queue-backed `Dispatcher` variant is a future path.
- **Plain-text tokens at rest in local config files.** Accepted for personal-use threat model; server stores only hashes.

---

## 3. Architecture

Three components, all Go, all single static binaries:

```
┌──────────────────────────────────────────────────────────────┐
│                         your machine                          │
│                                                               │
│   uncluster (CLI) ──HTTPS──┐                                 │
└────────────────────────────┼─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                   control plane (server)                      │
│   uncluster-server binary                                     │
│   ├── REST API (HTTP/JSON, listens on :7777)                 │
│   ├── SQLite at ~/.local/share/uncluster/uncluster.db        │
│   └── holds: nodes, tasks, task_chunks, tokens               │
└──────────────────────────────────────────────────────────────┘
                             ▲
                             │ nodes dial out
            ┌────────────────┼────────────────┐
            │                │                │
     ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐
     │   agent     │  │   agent     │  │   agent     │
     │ old-macbook │  │  home-srv   │  │  work-mbp   │
     └─────────────┘  └─────────────┘  └─────────────┘
       uncluster-agent, running as a user service (launchd/systemd)
```

### Transport

All HTTP. No WebSocket, no gRPC.

- **Agent → server, long-poll**: `GET /v1/agent/next-task` with 30 s timeout. Server returns a task immediately when one is pending, otherwise 204 → agent reconnects.
- **Agent → server, POST**: heartbeat every 10 s; chunk uploads during task execution; final completion POST.
- **CLI → server**: ordinary JSON requests; live output via SSE on `GET /v1/tasks/{id}/stream`.

### Why HTTP-only

- Works through every corporate/consumer proxy and NAT that permits outbound HTTPS.
- No long-lived connection management (reconnection, heartbeats, protocol negotiation) in V1.
- SSE covers live streaming cleanly without introducing a WebSocket dependency.
- Easy to port the server to TypeScript/Hono (Workers-compatible) later — OpenAPI is the contract.

### Security posture

- Control plane speaks HTTPS; **TLS is the operator's responsibility** (reverse proxy, Caddy, Cloudflare Tunnel, Tailscale). Server binary serves plain HTTP; certificate management is out of scope.
- Every request (agent and CLI) carries `Authorization: Bearer <token>`.
- Tokens stored only as hashes server-side; plaintext is shown exactly once at creation.

---

## 4. Data Model

SQLite schema for V1, portable to Postgres/MySQL/DynamoDB by way of the `Store` interface.

```sql
-- a registered machine
CREATE TABLE nodes (
  id              TEXT PRIMARY KEY,         -- uuid
  name            TEXT NOT NULL UNIQUE,     -- user-chosen, e.g. "old-macbook"
  token_hash      TEXT NOT NULL,            -- argon2id hash of long-lived agent token
  created_at      INTEGER NOT NULL,         -- unix seconds
  last_seen_at    INTEGER,                  -- updated on each heartbeat
  status          TEXT NOT NULL,            -- 'online' | 'offline' | 'revoked'
  metadata_json   TEXT NOT NULL DEFAULT '{}' -- latest heartbeat payload (free-form)
);

-- one-time join tokens and long-lived CLI tokens
CREATE TABLE tokens (
  id              TEXT PRIMARY KEY,         -- uuid
  kind            TEXT NOT NULL,            -- 'join' | 'cli'
  token_hash      TEXT NOT NULL,
  label           TEXT,                     -- human note
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER,                  -- nullable
  used_at         INTEGER                   -- join tokens are single-use
);

-- a unit of work
CREATE TABLE tasks (
  id              TEXT PRIMARY KEY,         -- uuid
  node_id         TEXT NOT NULL REFERENCES nodes(id),
  command         TEXT NOT NULL,            -- raw shell string
  status          TEXT NOT NULL,            -- 'pending' | 'running' | 'succeeded' | 'failed' | 'cancelling' | 'cancelled'
  exit_code       INTEGER,                  -- null until complete
  created_at      INTEGER NOT NULL,
  started_at      INTEGER,
  finished_at     INTEGER,
  created_by      TEXT                      -- cli token id, for audit
);

-- streamed output, append-only
CREATE TABLE task_chunks (
  task_id         TEXT NOT NULL REFERENCES tasks(id),
  seq             INTEGER NOT NULL,
  stream          TEXT NOT NULL,            -- 'stdout' | 'stderr'
  data            BLOB NOT NULL,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (task_id, seq)
);

CREATE INDEX idx_tasks_node_status ON tasks(node_id, status);
CREATE INDEX idx_tasks_created ON tasks(created_at DESC);
```

### Notes

- **`metadata_json` is a free-form blob.** Adding fields (GPU info, Tailscale IP, etc.) does not require a migration.
- **No separate task queue table.** Pending work is `tasks WHERE status='pending' AND node_id=?` ordered by `created_at`.
- **No retention policy in V1.** `uncluster tasks prune --older-than=7d` is a later command.
- **Tokens at rest are argon2id hashes.** A leaked DB alone cannot impersonate an agent or CLI.

---

## 5. API Surface

### 5.1 REST endpoints

The `api/openapi.yaml` file is the **source of truth** for the REST contract. Both the Go server and any future implementation (TS/Hono on Cloudflare Workers, etc.) generate types and stubs from it.

#### Agent-facing (auth: `Authorization: Bearer <agent-token>`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/agent/register` | Exchange a one-time join token for a long-lived agent token + node id. |
| POST | `/v1/agent/heartbeat` | Every 10 s. Updates `last_seen_at` and `metadata_json`. |
| GET | `/v1/agent/next-task` | Long-poll 30 s. Returns next pending task for this node, or 204. |
| POST | `/v1/agent/tasks/{id}/chunks` | Append stdout/stderr chunks. Body: `{ seq, stream, data }`. |
| POST | `/v1/agent/tasks/{id}/complete` | Final: `{ exit_code, finished_at }`. |

#### CLI-facing (auth: `Authorization: Bearer <cli-token>`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/nodes` | List nodes with current status + metadata. |
| GET | `/v1/nodes/{name_or_id}` | Node details. |
| DELETE | `/v1/nodes/{id}` | Remove a node (revokes its token). |
| POST | `/v1/tasks` | Create task `{ node, command }`. Returns task_id. |
| GET | `/v1/tasks?node=&status=&limit=` | List recent tasks. |
| GET | `/v1/tasks/{id}` | Task details (status, timings, exit code). |
| GET | `/v1/tasks/{id}/output` | Full stdout/stderr batched — blocks until task is complete. |
| GET | `/v1/tasks/{id}/stream` | SSE: live chunks + final status event. |
| POST | `/v1/tasks/{id}/cancel` | Cancel pending or running task. |
| POST | `/v1/tokens` | Create token `{ kind: "join"\|"cli", label?, expires_at? }`. Returns plaintext **once**. |
| GET | `/v1/tokens` | List (metadata only; never plaintext). |
| DELETE | `/v1/tokens/{id}` | Revoke token. |

#### Public (no auth)

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness. |

### 5.2 CLI surface

Single binary, `uncluster`, grouped subcommands:

```
# server-side (run on the control-plane host)
uncluster server start [--addr :7777] [--db path]
uncluster server token create --kind=join --label=old-macbook   # prints plaintext once
uncluster server token create --kind=cli   --label=my-laptop
uncluster server token ls
uncluster server token revoke <id>

# agent-side (run on each node)
uncluster agent join --server=URL --token=<join> --name=<node-name>
uncluster agent run                       # foreground, prints logs
uncluster agent install                   # installs launchd/systemd user service
uncluster agent uninstall

# client-side (run from your laptop)
uncluster nodes ls                        # table: name, os, cpu, mem, load, last-seen
uncluster nodes show <name>
uncluster nodes rm <name>

uncluster run <node> -- <cmd>...          # creates task + tails live; exits with task's exit code
uncluster run --async <node> -- <cmd>...  # prints task-id, returns

uncluster tasks ls [--node=X] [--status=Y]
uncluster tasks show <id>
uncluster tasks tail <id>                 # SSE live-tail
uncluster tasks cancel <id>

uncluster config set server=URL
uncluster config set token=<cli>
uncluster config show
```

### 5.3 V1 command priority

- **Must ship in V1:** `server start`, `server token create`, `agent join`, `agent run`, `nodes ls`, `run <node> -- <cmd>`, `tasks tail`, `tasks show`, and the `/v1/tasks/{id}/stream` SSE endpoint (required by `run` and `tasks tail`).
- **Nice to have in V1:** `agent install`, `tasks cancel`, `tasks ls`, `nodes rm`, token revocation.
- **Later:** `tasks prune`, multi-node fan-out, TUI dashboard, MCP server.

---

## 6. Registration & Auth Flow

### 6.1 Bringing up the control plane

```
# on the home-server machine
$ uncluster server start --addr :7777 --db ~/.local/share/uncluster/uncluster.db
listening on :7777

# mint a CLI token
$ uncluster server token create --kind=cli --label=my-laptop
token: uct_cli_8f2a9b...(shown ONCE, copy it now)
id:    tok_01H...

# on your laptop
$ uncluster config set server=https://uncluster.home.example.com:7777
$ uncluster config set token=uct_cli_8f2a9b...
$ uncluster nodes ls
(empty — no nodes yet)
```

### 6.2 Adding a node

```
# on the server: mint a one-time join token
$ uncluster server token create --kind=join --label=old-macbook
token: uct_join_4c7e...(valid 15 min, single-use)

# on the new machine (the old MacBook)
$ curl -L https://.../uncluster-agent-darwin-amd64 -o /usr/local/bin/uncluster
$ chmod +x /usr/local/bin/uncluster
$ uncluster agent join \
    --server=https://uncluster.home.example.com:7777 \
    --token=uct_join_4c7e... \
    --name=old-macbook

registered as node_01HX... (old-macbook)
agent token saved to ~/.config/uncluster/agent.toml
$ uncluster agent install
$ launchctl start com.uncluster.agent
```

### 6.3 Under the hood on `agent join`

1. Agent POSTs `/v1/agent/register` with `{ join_token, name, metadata }`.
2. Server validates the join token (present, unused, not expired, hash matches), creates a node row, generates a fresh long-lived **agent token**, stores only its hash, and marks the join token `used_at = now`.
3. Server responds with `{ node_id, agent_token }` — plaintext agent token returned exactly once.
4. Agent writes `~/.config/uncluster/agent.toml` (mode 0600):
   ```toml
   server      = "https://uncluster.home.example.com:7777"
   node_id     = "node_01HX..."
   node_name   = "old-macbook"
   agent_token = "uct_agent_..."
   ```
5. Agent never sends the join token again.

### 6.4 Steady state

- Every 10 s: `POST /v1/agent/heartbeat` with current metrics.
- Continuously: `GET /v1/agent/next-task` (30 s long-poll). On 204, immediately reconnect. On a task, execute; stream chunks; complete.
- All requests carry `Authorization: Bearer <agent-token>`. Server middleware maps the hash to a `node_id` and rejects tokens whose node is `status='revoked'`.

### 6.5 Revocation

- `uncluster nodes rm <name>` → server sets node `status='revoked'`, deletes the token row. Any in-flight long-poll returns 401; the agent exits cleanly.
- `uncluster server token revoke <id>` revokes a CLI token.

### 6.6 Token format & lifetime

Prefixes so leaked tokens are greppable and distinguishable at a glance:

| Prefix | Purpose | Expiry | Revocable |
|---|---|---|---|
| `uct_join_...` | One-time node registration | 15 minutes, single-use (whichever comes first) | N/A (consumed) |
| `uct_agent_...` | Long-lived agent credential | None | Yes (via `nodes rm` or direct token revoke) |
| `uct_cli_...` | CLI / automation credential | Optional `expires_at` at creation; default none | Yes |

Each token body is 32 bytes of CSPRNG output, base32-encoded, with the prefix prepended. Server stores only an argon2id hash; verification is hash-compare against `tokens.token_hash` (for CLI/join) or `nodes.token_hash` (for agent).

### 6.7 V1 simplifications (deliberate)

- Control plane serves plain HTTP; TLS is the operator's job.
- No token rotation — revoke and re-issue if something leaks.
- No RBAC. Every CLI token can do everything. Multi-user is §10.

---

## 7. Task Execution Flow

### 7.1 End-to-end timeline

```
$ uncluster run old-macbook -- bash -lc 'sleep 2; ls /; exit 0'
[task_01HY... on old-macbook]
bin
etc
...
usr
var
[exit 0 in 2.1s]
$ echo $?
0
```

```
┌──────────┐                 ┌───────────────┐                ┌──────────┐
│   CLI    │                 │ control plane │                │  agent   │
└────┬─────┘                 └───────┬───────┘                └────┬─────┘
     │                               │                             │
     │ POST /v1/tasks                │                             │
     │ {node, command}               │                             │
     │ ─────────────────────────────►│                             │
     │                               │  INSERT tasks               │
     │                               │  status=pending             │
     │                               │  dispatcher.Notify(node)    │
     │ ◄──── 201 {task_id}           │                             │
     │                               │                             │
     │                               │  ◄─── GET /v1/agent/next-task (long-poll, already waiting)
     │                               │  SELECT pending WHERE       │
     │                               │         node_id=... LIMIT 1 │
     │                               │  UPDATE status=running      │
     │                               │  started_at=now             │
     │                               │ 200 {task_id, command} ───► │
     │                               │                             │
     │ GET /v1/tasks/{id}/stream     │                             │
     │ (SSE)                         │                             │
     │ ─────────────────────────────►│                             │
     │ ◄─── event: status running    │                             │
     │                               │                             │ exec.Command
     │                               │                             │ pipes stdout/err
     │                               │ ◄── POST chunks (seq=0)     │
     │                               │     INSERT task_chunks      │
     │                               │     dispatcher.Publish      │
     │ ◄─── event: chunk stdout ...  │                             │
     │                               │ ◄── POST chunks (seq=1)     │
     │ ◄─── event: chunk             │                             │
     │                               │ ◄── POST complete           │
     │                               │     exit_code=0             │
     │                               │     UPDATE status=succeeded │
     │ ◄─── event: done {exit:0}     │                             │
     │ exit 0                        │                             │
```

### 7.2 Server-side dispatcher (V1, in-process)

```go
type Dispatcher interface {
    // Called by the API handler when a new task is inserted.
    Notify(nodeID string)

    // Called by the long-poll handler. Blocks up to `timeout` for a task on this node.
    // Returns nil on timeout.
    Wait(ctx context.Context, nodeID string, timeout time.Duration) *Task

    // For SSE streaming — publishes a chunk to any active listeners on this task.
    PublishChunk(taskID string, chunk Chunk)
    Subscribe(taskID string) (<-chan Event, func())  // returns stream + unsubscribe
}
```

V1 implementation: `map[nodeID]chan struct{}` for wake-ups + `map[taskID][]chan Event` for chunk subscribers, guarded by a mutex. Pending tasks are pulled from SQLite ordered by `created_at`.

Future Lambda/Workers variants replace `Notify`/`Wait` with queue semantics (SQS, Redis Streams, Durable Objects). `PublishChunk`/`Subscribe` become pub/sub on the same substrate. Handlers are unchanged.

### 7.3 Agent-side execution

```go
// pseudocode
for {
    task, err := server.NextTask(ctx)      // long-poll, blocks
    if err != nil { backoff(); continue }
    if task == nil { continue }            // 204 timeout, immediate reconnect

    cmd := exec.CommandContext(taskCtx, "bash", "-lc", task.Command)
    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()
    cmd.Start()

    go streamPipe(stdout, "stdout", task.ID)   // POST chunks as they come
    go streamPipe(stderr, "stderr", task.ID)

    err = cmd.Wait()
    exitCode := extractExitCode(err)
    server.CompleteTask(task.ID, exitCode)
}
```

Chunk flushing:
- when a single read fills a 4 KiB buffer, **or**
- every 200 ms if there is pending data, **or**
- immediately on process exit.

This gives live-tail without one HTTP request per byte.

### 7.4 Cancellation

The agent has no dedicated server→agent control channel (it only polls `next-task` and POSTs chunks/heartbeats). Cancellation rides on the two frequent agent→server calls.

- **Client call:** `POST /v1/tasks/{id}/cancel` marks `status='cancelling'`.
- **Signal delivery:** the next `POST /v1/agent/tasks/{id}/chunks` or `POST /v1/agent/heartbeat` from this node returns a response body with `{ cancel_task_ids: ["task_01HY..."] }`. Worst-case latency is therefore one heartbeat interval (10 s) even if the task produces no output. An idle agent mid-task still heartbeats.
- **Agent on receipt:** `taskCtx.Cancel()` → `SIGTERM` the child process group → wait 5 s → `SIGKILL` if still alive.
- **Agent reports** final status via the usual `POST /v1/agent/tasks/{id}/complete` with whatever exit code arrived; the server maps `status='cancelling'` + completion into `status='cancelled'`.

### 7.5 Failure modes handled in V1

| Scenario | Behavior |
|---|---|
| Agent crashes mid-task | On restart, agent has no in-flight task. Server sees `status=running` with no heartbeat for 60 s → reaper marks `status='failed'`, exit_code=-1, appends a `[agent lost]` chunk. |
| Server crashes mid-task | Agent keeps running. Chunk POSTs to a reaped task are rejected idempotently. |
| Network flap | Exponential backoff on POSTs; long-poll just reconnects. |
| Command not found / non-zero exit | Normal. `exit_code` carries it. |
| Chunk POST fails | Agent buffers in-memory up to 1 MB per task, drops oldest with a `[truncated]` marker. |

### 7.6 Out-of-scope for V1

- No scheduling / placement. If the named node is offline, the task sits `pending` until it returns (or is cancelled).
- No retry on failed tasks — caller concern.
- No output size cap beyond the 1 MB in-memory buffer.
- No stdin streaming to tasks.

---

## 8. Tech Stack & Project Layout

### 8.1 Dependencies

Go stdlib does most of the work. External deps kept deliberately small and boring.

| Concern | Choice | Rationale |
|---|---|---|
| HTTP server | `net/http` + `chi` router | stdlib + clean routing without a framework |
| CLI | `spf13/cobra` | best-in-class for multi-subcommand CLIs |
| Config | TOML via `BurntSushi/toml` | single file, no viper overkill |
| SQLite | `modernc.org/sqlite` (pure Go) | no cgo → trivial cross-compile |
| Migrations | hand-rolled `schema_version` + DDL slice | minimal surface area |
| UUIDs | `google/uuid` | boring, correct |
| Token hashing | `golang.org/x/crypto/argon2` | modern default |
| SSE | hand-rolled (~40 lines) | no library needed |
| Agent metrics | `shirou/gopsutil/v3` | cross-platform |
| HTTP testing | `httptest` | stdlib |
| Service install | `kardianos/service` | launchd/systemd/Windows uniform API |
| Process-group kill | `syscall.Kill(-pgid, SIGTERM/SIGKILL)` | needed for bash subchildren |
| OpenAPI codegen | `oapi-codegen` | generate server stubs + Go client from `api/openapi.yaml` |

**Deliberately not using:** ORM (hand-written SQL), gRPC (HTTP/JSON is plenty), Echo/Gin/Fiber (chi is enough), zap/logrus (`log/slog`), Docker.

### 8.2 Repo layout

```
uncluster/
├── cmd/
│   ├── uncluster/                  # the one binary, all subcommands
│   │   └── main.go
│   └── uncluster-agent/            # thin wrapper invoking `uncluster agent run`
│       └── main.go                 # for users who want an agent-only binary
├── internal/
│   ├── api/
│   │   ├── types.go                # generated from openapi.yaml
│   │   ├── client.go               # generated Go client
│   │   └── server.go               # generated handler interfaces
│   ├── server/
│   │   ├── handlers.go             # HTTP handlers implementing server.go
│   │   ├── middleware.go           # auth, logging, recovery
│   │   ├── dispatcher.go           # Dispatcher interface + in-process impl
│   │   └── sse.go                  # SSE helper
│   ├── store/
│   │   ├── store.go                # Store interface
│   │   ├── sqlite.go               # SQLite implementation
│   │   ├── migrations.go           # schema DDL
│   │   └── sqlite_test.go
│   ├── agent/
│   │   ├── agent.go                # main loop: heartbeat, poll, execute
│   │   ├── execute.go              # exec + streaming stdout/stderr
│   │   ├── metrics.go              # gopsutil wrappers
│   │   └── config.go               # ~/.config/uncluster/agent.toml
│   ├── cli/
│   │   ├── root.go                 # cobra root
│   │   ├── server_cmd.go           # `uncluster server ...`
│   │   ├── agent_cmd.go            # `uncluster agent ...`
│   │   ├── nodes_cmd.go            # `uncluster nodes ...`
│   │   ├── run_cmd.go              # `uncluster run`
│   │   ├── tasks_cmd.go            # `uncluster tasks ...`
│   │   └── config_cmd.go
│   ├── token/
│   │   ├── token.go                # generate, hash, verify, prefix handling
│   │   └── token_test.go
│   └── version/
│       └── version.go              # set via -ldflags at build
├── api/
│   └── openapi.yaml                # SOURCE OF TRUTH for REST contract
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-04-23-uncluster-v1-design.md   # this doc
├── scripts/
│   ├── build.sh                    # cross-compile all targets
│   └── generate.sh                 # oapi-codegen
├── .github/
│   └── workflows/
│       └── ci.yml                  # build, test, lint for linux/darwin, amd64/arm64
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

### 8.3 Build & distribution

- **Single binary, multiple entry points.** `uncluster` + subcommand selects role. Target size under 25 MB.
- **Cross-compile matrix:** `darwin/amd64`, `darwin/arm64`, `linux/amd64`, `linux/arm64`. Windows deferred.
- **Release artifacts:** tarballs with binary + example launchd/systemd unit + man page. GitHub Releases. `install.sh` nice-to-have.
- **Version stamping:** `-ldflags "-X .../version.Version=v0.1.0"`.

### 8.4 Config file locations

- Agent: `~/.config/uncluster/agent.toml` (`$XDG_CONFIG_HOME` if set)
- CLI: `~/.config/uncluster/cli.toml`
- Server: `~/.config/uncluster/server.toml`; DB defaults to `~/.local/share/uncluster/uncluster.db` (`$XDG_DATA_HOME`)

On macOS these remain under `~/.config` / `~/.local/share` for consistency with standard CLI-tool behavior, rather than `~/Library/...`.

### 8.5 Testing strategy

- **Unit tests per package.** Store layer tested against real in-memory SQLite (`file::memory:?cache=shared`), not mocks.
- **Integration tests** in `internal/server/integration_test.go`: spin up a real server on `127.0.0.1:0`, start an in-process agent, create a task, assert streaming output + exit code end-to-end.
- **No mocking of external services.** System is self-contained.
- **`go test ./... -race`** is the local default. CI adds `staticcheck`.

---

## 9. Future Extensibility Seams (Baked into V1)

These aren't features — they're V1 decisions that make future work cheap.

1. **`Store` interface** → Postgres, MySQL, DynamoDB later without touching handlers.
2. **`Dispatcher` interface** → queue-backed (SQS, Redis Streams) or polling variants for Lambda / serverless.
3. **OpenAPI as the contract** → a TypeScript/Hono control plane for Cloudflare Workers is a port of handlers + `Store` + `Dispatcher`, not a rewrite of the protocol. Lives in `servers/workers-ts/` when built.
4. **Agent → Server is always outbound HTTP** → agents never need public endpoints; overlay networks (Tailscale, Cloudflare Tunnel) just change the server URL.
5. **Tokens are hashed and prefixed** → rotation and per-token scoping are future additive changes, not schema reshapes.

---

## 10. Out of Scope & Non-Goals

### 10.1 Deliberately excluded from V1

| Feature | Why not V1 | Where it fits later |
|---|---|---|
| File transfer to/from nodes | Not in the minimum loop; scp/curl cover the common case. | Task model: optional `inputs[]` + `outputs[]` with content-addressed blobs in a `blobs` table. |
| Typed task capabilities | Shell covers 90%. Real usage should shape the API. | `/v1/agent/capabilities`; agent registers a manifest; tasks carry `kind` + typed `params`. |
| MCP server | CLI already lets AI drive it. MCP is sugar. | New `cmd/uncluster-mcp` shelling out to the REST client. |
| Multi-user / RBAC | Single-user tool. | `users` table; token → user mapping; per-route role checks. |
| Output retention / pruning | Accumulation isn't a problem at personal scale for months. | `uncluster tasks prune --older-than=7d`; optional auto-prune in server config. |
| Cross-node fan-out (`--all`) | Pure CLI sugar over `POST /v1/tasks` in a loop. | CLI only; no server changes. |
| Task retry on failure | Caller concern. | Optional `retry: { max, backoff }` on task create. |
| Stdin streaming | Rare for ad-hoc commands. | New agent endpoint pair for stdin. |
| Web UI / TUI dashboard | Nice but not load-bearing. | Separate binary, or `uncluster --tui` flag. |
| Cron / scheduled tasks | Outside the "just run something" vision. | `schedules` table + server ticker, or just `cron` + `uncluster run`. |
| Secrets / env injection | Shell `export` works. | `task.env` field; encrypted at rest later. |
| Resource quotas / priority | Not a real problem yet. | Node-side: `nice`/`cgroups`; server-side: priority field. |

### 10.2 Non-goals the project will never become

- **Not Kubernetes.** No scheduling, no constraints, no pods, no controllers.
- **Not a PaaS.** No "push to deploy," no service model, no user-facing reverse proxy.
- **Not multi-tenant.** One operator, one set of machines.
- **Not a job queue.** Pending tasks happen to queue, but this isn't Sidekiq / Celery.
- **Not a monitoring system.** Heartbeat metadata answers "is this box alive and what does it look like," not time-series dashboards.

---

## 11. V1 Acceptance Criteria

V1 is done when, on a fresh machine:

1. Operator can run `uncluster server start` and see `:7777` listening.
2. Operator can run `uncluster server token create --kind=cli` on the server, then `uncluster config set` + `uncluster nodes ls` on a laptop — returns empty list, 200 OK.
3. Operator can run `uncluster server token create --kind=join`, then `uncluster agent join …` on a second machine — node appears in `uncluster nodes ls` with live metadata.
4. Agent, if killed and restarted, re-appears in `uncluster nodes ls` within one heartbeat interval (~10 s).
5. `uncluster run <node> -- <cmd>` executes on the target and streams output live; exit code is propagated to the CLI.
6. `uncluster tasks tail <id>` attaches to an already-running task and streams remaining output.
7. `uncluster nodes rm <node>` revokes the node's token; the agent's next request returns 401 and it exits cleanly.
8. End-to-end integration test covers #1–#5 in CI.
9. Static binaries for `darwin/{amd64,arm64}` and `linux/{amd64,arm64}` build in CI, each ≤ 25 MB.
10. `api/openapi.yaml` exists, `oapi-codegen` generates client/server stubs, and the Go server implements every path it lists.
