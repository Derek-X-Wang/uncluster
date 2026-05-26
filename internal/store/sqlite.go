package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"lukechampine.com/blake3"
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
	// Ensure schema_version row exists. Note: PRIMARY KEY is `version` itself,
	// so naive `INSERT OR IGNORE VALUES (0)` adds a second row once version has
	// been bumped (since e.g. (0) doesn't conflict with an existing (19) row).
	// We instead insert (0) only when the table is empty, and read via MAX()
	// so any legacy multi-row state is healed transparently on next start.
	if _, err := s.db.Exec(migrations[1]); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	if _, err := s.db.Exec(`INSERT INTO schema_version(version) SELECT 0 WHERE NOT EXISTS(SELECT 1 FROM schema_version)`); err != nil {
		return fmt.Errorf("seed schema_version: %w", err)
	}
	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
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
	id := p.ID
	if id == "" {
		id = shortID(16)
	}
	now := time.Now()
	var expiresAt *int64
	if p.ExpiresAt != nil {
		v := p.ExpiresAt.Unix()
		expiresAt = &v
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens(id, kind, agent_id, secret_hash, label, created_at, expires_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		id, string(p.Kind), p.AgentID, p.SecretHash, p.Label, now.Unix(), expiresAt)
	if err != nil {
		return Token{}, fmt.Errorf("insert token: %w", err)
	}
	return s.GetTokenByID(ctx, id)
}

func (s *sqliteStore) GetTokenByID(ctx context.Context, id string) (Token, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, kind, agent_id, secret_hash, label, created_at, expires_at, used_at, revoked_at
		 FROM tokens WHERE id = ?`, id)
	return scanToken(row)
}

func (s *sqliteStore) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, agent_id, secret_hash, label, created_at, expires_at, used_at, revoked_at
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
		agentID                      sql.NullString
		label                        sql.NullString
		expiresAt, usedAt, revokedAt sql.NullInt64
		createdAt                    int64
	)
	if err := r.Scan(&t.ID, &t.Kind, &agentID, &t.SecretHash, &label, &createdAt, &expiresAt, &usedAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Token{}, ErrNotFound
		}
		return Token{}, err
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	if agentID.Valid {
		v := agentID.String
		t.AgentID = &v
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

// ------------- agents (V2) -------------

func (s *sqliteStore) CreateAgent(ctx context.Context, p NewAgentParams) (Agent, error) {
	id := "ag_" + shortID(24)
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agents(id, name, created_at, status, agent_version)
		 VALUES(?, ?, ?, ?, '')`,
		id, p.Name, now.Unix(), string(AgentOnline))
	if err != nil {
		if isUniqueViolation(err) {
			return Agent{}, ErrAgentNameTaken
		}
		return Agent{}, fmt.Errorf("insert agent: %w", err)
	}
	return s.GetAgent(ctx, id)
}

func (s *sqliteStore) GetAgent(ctx context.Context, id string) (Agent, error) {
	return s.queryAgent(ctx, `WHERE id = ?`, id)
}

func (s *sqliteStore) GetAgentByName(ctx context.Context, name string) (Agent, error) {
	return s.queryAgent(ctx, `WHERE name = ?`, name)
}

func (s *sqliteStore) queryAgent(ctx context.Context, where string, arg any) (Agent, error) {
	q := `SELECT id, name, created_at, last_seen_at, status, agent_version, fail_closed_after FROM agents ` + where
	return scanAgent(s.db.QueryRowContext(ctx, q, arg))
}

func (s *sqliteStore) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, created_at, last_seen_at, status, agent_version, fail_closed_after
		 FROM agents WHERE status != 'revoked' ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *sqliteStore) RevokeAgent(ctx context.Context, id string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var currentName string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM agents WHERE id = ?`, id).Scan(&currentName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	newName := fmt.Sprintf("%s-revoked-%d", currentName, at.Unix())
	if _, err := tx.ExecContext(ctx,
		`UPDATE agents SET status = 'revoked', name = ? WHERE id = ?`, newName, id); err != nil {
		return err
	}
	// Revoke the agent token(s) linked to this agent.
	if _, err := tx.ExecContext(ctx,
		`UPDATE tokens SET revoked_at = ?
		 WHERE agent_id = ? AND kind = 'agent' AND revoked_at IS NULL`,
		at.Unix(), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *sqliteStore) SetAgentFailClosedAfter(ctx context.Context, id string, seconds *int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET fail_closed_after = ? WHERE id = ? AND status != 'revoked'`,
		seconds, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanAgent(r rowScanner) (Agent, error) {
	var (
		a                Agent
		lastSeen         sql.NullInt64
		agentVersion     sql.NullString
		failClosedAfter  sql.NullInt64
		createdAt        int64
	)
	if err := r.Scan(&a.ID, &a.Name, &createdAt, &lastSeen, &a.Status, &agentVersion, &failClosedAfter); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Agent{}, ErrNotFound
		}
		return Agent{}, err
	}
	a.CreatedAt = time.Unix(createdAt, 0)
	if lastSeen.Valid {
		v := time.Unix(lastSeen.Int64, 0)
		a.LastSeenAt = &v
	}
	if agentVersion.Valid {
		a.AgentVersion = agentVersion.String
	}
	if failClosedAfter.Valid {
		a.FailClosedAfter = &failClosedAfter.Int64
	}
	return a, nil
}

func (s *sqliteStore) UpdateAgentHeartbeat(ctx context.Context, id, agentVersion string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen_at = ?, agent_version = ?, status = ? WHERE id = ?`,
		at.Unix(), agentVersion, string(AgentOnline), id)
	return err
}

func (s *sqliteStore) UpsertAgentPolicyState(ctx context.Context, p UpsertAgentPolicyStateParams) error {
	now := time.Now().Unix()
	// desired_version column is NOT NULL (migration 11). Represent "no desired
	// version" as 0; translate back to nil on read.
	desiredVer := int64(0)
	if p.DesiredVersion != nil {
		desiredVer = *p.DesiredVersion
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_policy_state
		   (agent_id, desired_version, applied_version, applied_hash,
		    last_apply_status, last_apply_error, last_apply_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(agent_id) DO UPDATE SET
		   desired_version   = excluded.desired_version,
		   applied_version   = excluded.applied_version,
		   applied_hash      = excluded.applied_hash,
		   last_apply_status = excluded.last_apply_status,
		   last_apply_error  = excluded.last_apply_error,
		   last_apply_at     = excluded.last_apply_at,
		   updated_at        = excluded.updated_at`,
		p.AgentID, desiredVer, p.AppliedVersion, p.AppliedHash,
		p.LastApplyStatus, p.LastApplyError, p.LastApplyAt.Unix(), now)
	return err
}

func (s *sqliteStore) GetAgentPolicyState(ctx context.Context, agentID string) (AgentPolicyState, error) {
	var (
		ps             AgentPolicyState
		desiredVersion int64 // NOT NULL in schema; 0 = "no desired version"
		lastApplyError sql.NullString
		lastApplyAt    sql.NullInt64
		updatedAt      sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT agent_id, desired_version, applied_version, applied_hash,
		        last_apply_status, last_apply_error, last_apply_at, updated_at
		 FROM agent_policy_state WHERE agent_id = ?`, agentID).
		Scan(&ps.AgentID, &desiredVersion, &ps.AppliedVersion, &ps.AppliedHash,
			&ps.LastApplyStatus, &lastApplyError, &lastApplyAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AgentPolicyState{}, ErrNotFound
		}
		return AgentPolicyState{}, err
	}
	// 0 = sentinel for "no desired version pushed yet".
	if desiredVersion != 0 {
		ps.DesiredVersion = &desiredVersion
	}
	if lastApplyError.Valid {
		ps.LastApplyError = &lastApplyError.String
	}
	if lastApplyAt.Valid {
		ps.LastApplyAt = time.Unix(lastApplyAt.Int64, 0)
	}
	if updatedAt.Valid {
		ps.UpdatedAt = time.Unix(updatedAt.Int64, 0)
	}
	return ps, nil
}

// ------------- acl (V2) -------------

func (s *sqliteStore) CreateACL(ctx context.Context, p CreateACLParams) (ACLEntry, error) {
	id := "acl_" + shortID(24)
	now := time.Now()
	// Transactional: ACL insert + policy version bump must commit together.
	// Without this, a transient failure in the bump leaves an ACL row visible
	// to /v1/certs (which signs based on the row) while the Agent's principals
	// projection still reflects the old policy version — sshd then rejects
	// the freshly-issued cert because the principal isn't in the file. See #40.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ACLEntry{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO acl(id, caller_token_id, agent_id, username, created_at, created_by)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		id, p.CallerTokenID, p.AgentID, p.Username, now.Unix(), p.CreatedBy)
	if err != nil {
		if isUniqueViolation(err) {
			// Idempotent: re-grant returns the existing entry. Release the tx
			// before the second read — MaxOpenConns=1, so leaving the tx open
			// while calling getACLByTriple (which uses s.db) deadlocks.
			_ = tx.Rollback()
			return s.getACLByTriple(ctx, p.CallerTokenID, p.AgentID, p.Username)
		}
		return ACLEntry{}, fmt.Errorf("insert acl: %w", err)
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, p.AgentID); err != nil {
		return ACLEntry{}, fmt.Errorf("bump policy version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ACLEntry{}, fmt.Errorf("commit acl create: %w", err)
	}
	return s.GetACL(ctx, id)
}

func (s *sqliteStore) GetACL(ctx context.Context, id string) (ACLEntry, error) {
	return s.scanACL(s.db.QueryRowContext(ctx,
		`SELECT id, caller_token_id, agent_id, username, created_at, created_by FROM acl WHERE id = ?`, id))
}

func (s *sqliteStore) getACLByTriple(ctx context.Context, callerTokenID, agentID, username string) (ACLEntry, error) {
	return s.scanACL(s.db.QueryRowContext(ctx,
		`SELECT id, caller_token_id, agent_id, username, created_at, created_by
		 FROM acl WHERE caller_token_id = ? AND agent_id = ? AND username = ?`,
		callerTokenID, agentID, username))
}

func (s *sqliteStore) scanACL(r rowScanner) (ACLEntry, error) {
	var (
		e         ACLEntry
		createdAt int64
		createdBy sql.NullString
	)
	if err := r.Scan(&e.ID, &e.CallerTokenID, &e.AgentID, &e.Username, &createdAt, &createdBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ACLEntry{}, ErrNotFound
		}
		return ACLEntry{}, err
	}
	e.CreatedAt = time.Unix(createdAt, 0)
	if createdBy.Valid {
		e.CreatedBy = &createdBy.String
	}
	return e, nil
}

func (s *sqliteStore) DeleteACL(ctx context.Context, id string) error {
	// Transactional: read the row's agent_id (to know which policy to bump),
	// DELETE, and bump must all commit together. See CreateACL comment / #40.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Look up agent_id inside the tx so we read a consistent snapshot.
	var agentID string
	err = tx.QueryRowContext(ctx,
		`SELECT agent_id FROM acl WHERE id = ?`, id).Scan(&agentID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup acl: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM acl WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete acl: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Race: row vanished between SELECT and DELETE (e.g. cascade from
		// a concurrent agent deletion). The tx will roll back; report as not
		// found so the caller sees a consistent answer.
		return ErrNotFound
	}
	if err := s.bumpPolicyVersionTx(ctx, tx, agentID); err != nil {
		return fmt.Errorf("bump policy version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit acl delete: %w", err)
	}
	return nil
}

func (s *sqliteStore) ListACL(ctx context.Context, f ListACLFilter) ([]ACLEntry, error) {
	where := "1=1"
	var args []any
	if f.CallerTokenID != "" {
		where += " AND caller_token_id = ?"
		args = append(args, f.CallerTokenID)
	}
	if f.AgentID != "" {
		where += " AND agent_id = ?"
		args = append(args, f.AgentID)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, caller_token_id, agent_id, username, created_at, created_by
		 FROM acl WHERE `+where+` ORDER BY created_at ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ACLEntry
	for rows.Next() {
		e, err := s.scanACL(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// bumpPolicyVersion increments the monotonic policy version for an agent and
// recomputes the hash from current ACL rows. Upserts the row if absent.
// Standalone callers (no existing tx) use this; it opens its own tx.
func (s *sqliteStore) bumpPolicyVersion(ctx context.Context, agentID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.bumpPolicyVersionTx(ctx, tx, agentID); err != nil {
		return err
	}
	return tx.Commit()
}

// bumpPolicyVersionTx is the inner half: runs the bump statements within the
// caller's transaction. Callers (CreateACL, DeleteACL) compose this with their
// own ACL-row mutation so the whole operation is atomic — either both the ACL
// row change and the version bump commit, or neither does. See #40.
func (s *sqliteStore) bumpPolicyVersionTx(ctx context.Context, tx *sql.Tx, agentID string) error {
	// Upsert version row.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_policy_versions(agent_id, version, hash)
		 VALUES(?, 1, '')
		 ON CONFLICT(agent_id) DO UPDATE SET version = version + 1`,
		agentID); err != nil {
		return err
	}
	// Recompute hash from current ACL (must read the ACL within the same tx so
	// the hash reflects the row-change in flight, not a pre-change snapshot).
	h, err := computePolicyHash(ctx, tx, agentID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_policy_versions SET hash = ? WHERE agent_id = ?`, h, agentID); err != nil {
		return err
	}
	return nil
}

// GetPolicySnapshot returns the current policy projection for an agent.
// Returns a zero-version empty snapshot (no error) if no ACL rows exist.
//
// All reads run inside a single deferred read transaction so the returned
// (version, hash, principals) come from one consistent point in time. Without
// this, a concurrent ACL change between the version read and the principals
// read returned a torn snapshot — the Agent's applied_hash would never match
// the desired_hash and the server would re-push policy in a loop. See #41.
func (s *sqliteStore) GetPolicySnapshot(ctx context.Context, agentID string) (PolicySnapshot, error) {
	// Read-only tx. SQLite's default deferred isolation is sufficient: WAL mode
	// gives each tx a consistent read snapshot at the point of its first read,
	// and the writer side already serialises via MaxOpenConns(1).
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("begin read tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var version int64
	var hash string
	err = tx.QueryRowContext(ctx,
		`SELECT version, hash FROM agent_policy_versions WHERE agent_id = ?`, agentID).
		Scan(&version, &hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return PolicySnapshot{}, err
	}
	// Either no version row or version=0 → return empty snapshot at version 0.
	// The agent should apply an empty principals map (wipe all principals files).

	rows, err := tx.QueryContext(ctx,
		`SELECT username, caller_token_id FROM acl WHERE agent_id = ? ORDER BY username, caller_token_id`, agentID)
	if err != nil {
		return PolicySnapshot{}, err
	}
	defer rows.Close()

	byUser := map[string][]string{}
	var order []string
	for rows.Next() {
		var u, c string
		if err := rows.Scan(&u, &c); err != nil {
			return PolicySnapshot{}, err
		}
		if _, seen := byUser[u]; !seen {
			order = append(order, u)
		}
		byUser[u] = append(byUser[u], c)
	}
	if err := rows.Err(); err != nil {
		return PolicySnapshot{}, err
	}

	principals := make([]PolicyPrincipal, 0, len(order))
	for _, u := range order {
		principals = append(principals, PolicyPrincipal{Username: u, CallerTokenIDs: byUser[u]})
	}

	return PolicySnapshot{
		AgentID:    agentID,
		Version:    version,
		Hash:       hash,
		Principals: principals,
	}, nil
}

type dbQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// computePolicyHash calculates blake3:<hex> over the canonical serialisation:
// sorted "username:caller1,caller2\n" lines (callers sorted within each user).
// Returns "" for an empty ACL.
func computePolicyHash(ctx context.Context, db dbQueryer, agentID string) (string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT username, caller_token_id FROM acl WHERE agent_id = ? ORDER BY username, caller_token_id`, agentID)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var lines []byte
	for rows.Next() {
		var u, c string
		if err := rows.Scan(&u, &c); err != nil {
			return "", err
		}
		lines = append(lines, []byte(u+":"+c+"\n")...)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", nil
	}
	sum := blake3.Sum256(lines)
	return fmt.Sprintf("blake3:%x", sum), nil
}

// ------------- agent endpoints (V2) -------------

func (s *sqliteStore) UpsertAgentEndpoints(ctx context.Context, agentID string, endpoints []AgentEndpoint) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Replace all endpoints for this agent atomically.
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_endpoints WHERE agent_id = ?`, agentID); err != nil {
		return err
	}
	for _, e := range endpoints {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO agent_endpoints(agent_id, subnet, address) VALUES(?, ?, ?)`,
			agentID, e.Subnet, e.Address); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *sqliteStore) ListAgentEndpoints(ctx context.Context, agentID string) ([]AgentEndpoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT subnet, address FROM agent_endpoints WHERE agent_id = ? ORDER BY subnet`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentEndpoint
	for rows.Next() {
		var e AgentEndpoint
		if err := rows.Scan(&e.Subnet, &e.Address); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ------------- cert events (V2 — S6) -------------

func (s *sqliteStore) WriteCertEvent(ctx context.Context, e CertEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO cert_issuance_events
		   (request_id, ts, caller_token_id, target_agent_id, username,
		    cert_principal, pubkey_fp, ttl_seconds, serial, key_id, outcome, denial_reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.RequestID, e.TS.Unix(),
		nullString(e.CallerTokenID), nullString(e.TargetAgentID), nullString(e.Username),
		nullString(e.CertPrincipal), nullString(e.PubkeyFP),
		e.TTLSeconds, e.Serial, nullString(e.KeyID),
		e.Outcome, nullString(e.DenialReason),
	)
	return err
}

func (s *sqliteStore) ListCertEvents(ctx context.Context, f CertEventFilter) ([]CertEvent, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	where := "1=1"
	var args []any
	if f.CallerTokenID != "" {
		where += " AND caller_token_id = ?"
		args = append(args, f.CallerTokenID)
	}
	if f.AgentID != "" {
		where += " AND target_agent_id = ?"
		args = append(args, f.AgentID)
	}
	if f.Username != "" {
		where += " AND username = ?"
		args = append(args, f.Username)
	}
	if f.Outcome != "" {
		where += " AND outcome = ?"
		args = append(args, f.Outcome)
	}
	if f.Since != nil {
		where += " AND ts >= ?"
		args = append(args, f.Since.Unix())
	}
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx,
		`SELECT request_id, ts, caller_token_id, target_agent_id, username,
		        cert_principal, pubkey_fp, ttl_seconds, serial, key_id, outcome, denial_reason
		 FROM cert_issuance_events
		 WHERE `+where+` ORDER BY ts DESC LIMIT ?`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CertEvent
	for rows.Next() {
		var e CertEvent
		var ts int64
		var callerID, agentID, username, principal, fp, keyID, denial sql.NullString
		var serial sql.NullInt64
		if err := rows.Scan(
			&e.RequestID, &ts, &callerID, &agentID, &username,
			&principal, &fp, &e.TTLSeconds, &serial, &keyID,
			&e.Outcome, &denial,
		); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		if callerID.Valid {
			e.CallerTokenID = callerID.String
		}
		if agentID.Valid {
			e.TargetAgentID = agentID.String
		}
		if username.Valid {
			e.Username = username.String
		}
		if principal.Valid {
			e.CertPrincipal = principal.String
		}
		if fp.Valid {
			e.PubkeyFP = fp.String
		}
		if serial.Valid {
			e.Serial = uint64(serial.Int64)
		}
		if keyID.Valid {
			e.KeyID = keyID.String
		}
		if denial.Valid {
			e.DenialReason = denial.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ------------- update policy (S8b) -------------

// GetUpdatePolicy returns the current update policy. Returns ErrNotFound when
// no policy has been set yet (table is empty).
func (s *sqliteStore) GetUpdatePolicy(ctx context.Context) (UpdatePolicy, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT expected_version, asset_url_template, sha256_url_template, force, updated_at
		 FROM update_policy WHERE id = 1`)
	var p UpdatePolicy
	var updatedAt int64
	var force int
	if err := row.Scan(&p.ExpectedVersion, &p.AssetURLTemplate, &p.SHA256URLTemplate, &force, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UpdatePolicy{}, ErrNotFound
		}
		return UpdatePolicy{}, err
	}
	p.Force = force != 0
	p.UpdatedAt = time.Unix(updatedAt, 0)
	return p, nil
}

// SetUpdatePolicy upserts the single update_policy row.
func (s *sqliteStore) SetUpdatePolicy(ctx context.Context, p SetUpdatePolicyParams) error {
	now := time.Now().Unix()
	force := 0
	if p.Force {
		force = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO update_policy(id, expected_version, asset_url_template, sha256_url_template, force, updated_at)
		 VALUES(1, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			expected_version    = excluded.expected_version,
			asset_url_template  = excluded.asset_url_template,
			sha256_url_template = excluded.sha256_url_template,
			force               = excluded.force,
			updated_at          = excluded.updated_at`,
		p.ExpectedVersion, p.AssetURLTemplate, p.SHA256URLTemplate, force, now)
	return err
}

// nullString converts an empty Go string to SQL NULL; non-empty strings are returned as-is.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ------------- test hooks -------------

// TestInsertHook is a test-only seam for token fixture insertion.
// Not exported in the Store interface; tests type-assert against the concrete SQLite impl.
type TestInsertHook interface {
	InsertTokenWithID(ctx context.Context, id string, kind TokenKind, agentID *string, secretHash, label string) (Token, error)
}

func (s *sqliteStore) InsertTokenWithID(ctx context.Context, id string, kind TokenKind, agentID *string, secretHash, label string) (Token, error) {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens(id, kind, agent_id, secret_hash, label, created_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		id, string(kind), agentID, secretHash, label, now.Unix())
	if err != nil {
		return Token{}, err
	}
	return s.GetTokenByID(ctx, id)
}
