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
		t                            Token
		nodeID                       sql.NullString
		label                        sql.NullString
		expiresAt, usedAt, revokedAt sql.NullInt64
		createdAt                    int64
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
		n         Node
		lastSeen  sql.NullInt64
		createdAt int64
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

// ------------- stubs for unimplemented Store methods (future tasks) -------------

func (s *sqliteStore) CreateTask(ctx context.Context, nodeID, command, createdBy string, at time.Time) (Task, error) {
	return Task{}, fmt.Errorf("not implemented")
}

func (s *sqliteStore) GetTask(ctx context.Context, id string) (Task, error) {
	return Task{}, fmt.Errorf("not implemented")
}

func (s *sqliteStore) ListTasks(ctx context.Context, nodeID string, status TaskStatus, limit int) ([]Task, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStore) ClaimNextPending(ctx context.Context, nodeID string, at time.Time) (*Task, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStore) CompleteTask(ctx context.Context, id string, exitCode int, at time.Time) error {
	return fmt.Errorf("not implemented")
}

func (s *sqliteStore) MarkTaskCancelling(ctx context.Context, id string) error {
	return fmt.Errorf("not implemented")
}

func (s *sqliteStore) MarkTaskCancelled(ctx context.Context, id string, at time.Time) error {
	return fmt.Errorf("not implemented")
}

func (s *sqliteStore) MarkTaskFailedLost(ctx context.Context, id string, at time.Time) error {
	return fmt.Errorf("not implemented")
}

func (s *sqliteStore) PendingCancelsForNode(ctx context.Context, nodeID string) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStore) FindStaleRunning(ctx context.Context, olderThan time.Time) ([]Task, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStore) AppendChunk(ctx context.Context, taskID, stream string, data []byte, at time.Time, maxBytes int64) (ChunkAppendResult, error) {
	return ChunkAppendResult{}, fmt.Errorf("not implemented")
}

func (s *sqliteStore) ListChunks(ctx context.Context, taskID, stream string, sinceSeq int64, limit int) ([]Chunk, error) {
	return nil, fmt.Errorf("not implemented")
}
