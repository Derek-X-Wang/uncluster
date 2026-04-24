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
