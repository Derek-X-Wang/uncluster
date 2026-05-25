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

	// ---- V2 (S1) ----
	// agents coexist with V1 nodes during transition. S11 drops nodes/tasks/chunks
	// and renames callsites. V2 code references agents only.

	// 6: agents
	`CREATE TABLE agents (
		id                TEXT PRIMARY KEY,
		name              TEXT NOT NULL UNIQUE,
		created_at        INTEGER NOT NULL,
		last_seen_at      INTEGER,
		status            TEXT NOT NULL,
		agent_version     TEXT NOT NULL DEFAULT '',
		fail_closed_after INTEGER
	)`,

	// 7: agent_subnets
	`CREATE TABLE agent_subnets (
		agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		subnet   TEXT NOT NULL,
		PRIMARY KEY (agent_id, subnet)
	)`,
	`CREATE INDEX idx_agent_subnets_subnet ON agent_subnets(subnet)`,

	// 8: agent_endpoints
	`CREATE TABLE agent_endpoints (
		agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		subnet   TEXT NOT NULL,
		address  TEXT NOT NULL,
		PRIMARY KEY (agent_id, subnet)
	)`,

	// 9: acl
	`CREATE TABLE acl (
		id              TEXT PRIMARY KEY,
		caller_token_id TEXT NOT NULL,
		agent_id        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		username        TEXT NOT NULL,
		created_at      INTEGER NOT NULL,
		created_by      TEXT,
		UNIQUE (caller_token_id, agent_id, username)
	)`,
	`CREATE INDEX idx_acl_caller ON acl(caller_token_id)`,
	`CREATE INDEX idx_acl_agent ON acl(agent_id)`,

	// 10: cert_issuance_events (writes start in S6; schema lands here)
	`CREATE TABLE cert_issuance_events (
		request_id      TEXT PRIMARY KEY,
		ts              INTEGER NOT NULL,
		caller_token_id TEXT NOT NULL,
		target_agent_id TEXT,
		username        TEXT,
		cert_principal  TEXT,
		pubkey_fp       TEXT,
		ttl_seconds     INTEGER,
		serial          INTEGER,
		key_id          TEXT,
		outcome         TEXT NOT NULL,
		denial_reason   TEXT
	)`,
	`CREATE INDEX idx_cert_events_caller ON cert_issuance_events(caller_token_id, ts DESC)`,
	`CREATE INDEX idx_cert_events_agent ON cert_issuance_events(target_agent_id, ts DESC)`,

	// 11: agent_policy_state
	`CREATE TABLE agent_policy_state (
		agent_id          TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
		desired_version   INTEGER NOT NULL DEFAULT 0,
		applied_version   INTEGER NOT NULL DEFAULT 0,
		applied_hash      TEXT NOT NULL DEFAULT '',
		last_apply_status TEXT,
		last_apply_error  TEXT,
		last_apply_at     INTEGER
	)`,

	// ---- V2 (S2a) ----

	// 12: link agent tokens to the V2 agents table. The V1 tokens.node_id
	// column stays intact for V1 node tokens. V2 agent tokens use agent_id
	// instead; node_id is left NULL for those rows.
	`ALTER TABLE tokens ADD COLUMN agent_id TEXT REFERENCES agents(id)`,
	`CREATE INDEX idx_tokens_agent ON tokens(agent_id)`,

	// ---- V2 (S3a) ----

	// 13: add updated_at to agent_policy_state for heartbeat timestamp tracking.
	`ALTER TABLE agent_policy_state ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0`,

	// ---- V2 (S3b) ----

	// 14: monotonic policy version counter per agent. Incremented whenever an
	// ACL row touching agent_id is created or deleted. Hash tracks the canonical
	// blake3 hash of the resulting policy snapshot.
	`CREATE TABLE agent_policy_versions (
		agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
		version  INTEGER NOT NULL DEFAULT 0,
		hash     TEXT NOT NULL DEFAULT ''
	)`,

	// ---- V2 (S11) ----

	// 15: drop V1 task_chunks, tasks, nodes tables (in dependency order).
	// Disable FK enforcement for this migration block: the tokens table has a
	// dangling FK on nodes(id) from migration 3, and SQLite with FK pragma ON
	// will refuse to insert NULL node_id into tokens if nodes no longer exists.
	// We recreate tokens without that column after dropping nodes.
	`DROP TABLE IF EXISTS task_chunks`,
	`DROP TABLE IF EXISTS tasks`,

	// 16: rebuild tokens without the node_id FK column (SQLite requires table
	// recreation to remove a column/FK). Copy all rows preserving agent_id.
	`CREATE TABLE tokens_v2 (
		id          TEXT PRIMARY KEY,
		kind        TEXT NOT NULL,
		agent_id    TEXT REFERENCES agents(id),
		secret_hash TEXT NOT NULL,
		label       TEXT NOT NULL DEFAULT '',
		created_at  INTEGER NOT NULL,
		expires_at  INTEGER,
		used_at     INTEGER,
		revoked_at  INTEGER
	)`,
	`INSERT INTO tokens_v2(id, kind, agent_id, secret_hash, label, created_at, expires_at, used_at, revoked_at)
	 SELECT id, kind, agent_id, secret_hash, label, created_at, expires_at, used_at, revoked_at
	 FROM tokens`,
	`DROP TABLE tokens`,
	`ALTER TABLE tokens_v2 RENAME TO tokens`,
	`CREATE INDEX idx_tokens_agent ON tokens(agent_id)`,
	`DROP TABLE IF EXISTS nodes`,

	// ---- V2 (S8b) ----

	// 17: update_policy — server-side expected version + asset URL template.
	// Single-row table (id=1); upserted by operator CLI.
	`CREATE TABLE update_policy (
		id                   INTEGER PRIMARY KEY CHECK (id = 1),
		expected_version      TEXT NOT NULL DEFAULT '',
		asset_url_template    TEXT NOT NULL DEFAULT '',
		sha256_url_template   TEXT NOT NULL DEFAULT '',
		force                 INTEGER NOT NULL DEFAULT 0,
		updated_at            INTEGER NOT NULL
	)`,
}
