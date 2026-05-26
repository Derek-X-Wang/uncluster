package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// TestACL_TransactionalContract proves the fix for #40: CreateACL and
// DeleteACL each commit the ACL row change and the policy-version bump in a
// single sql.Tx. If the bump fails, the row change must roll back too.
//
// Without the fix, `INSERT INTO acl` was autocommitted before
// `bumpPolicyVersion` opened its own tx — a bump failure left a phantom ACL
// row whose policy projection (the Agent's principals file) did not include
// the new caller. /v1/certs would happily sign a cert for that caller; sshd
// would reject it ("Principal not in AuthorizedPrincipalsFile").
//
// Test mechanism: install a SQLite trigger that raises an error on any UPDATE
// to agent_policy_versions. CreateACL/DeleteACL hit the bump UPDATE inside
// their tx and must roll back the ACL change. We then assert:
//  1. CreateACL returned an error.
//  2. The ACL table contains zero rows (the insert was rolled back).
//  3. agent_policy_versions reflects no bump beyond the prior state.
//
// We're inside `package store` here so we can poke `sqliteStore.db` directly
// to install the trigger without exposing internals as public API.
func TestACL_TransactionalContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acltx.db")
	rawStore, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawStore.Close() })
	st := rawStore.(*sqliteStore)
	ctx := context.Background()

	ag, err := st.CreateAgent(ctx, NewAgentParams{Name: "tx-agent"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := st.CreateToken(ctx, NewTokenParams{Kind: TokenCaller, SecretHash: "h"})
	if err != nil {
		t.Fatal(err)
	}

	// First CreateACL succeeds, leaving agent_policy_versions.version = 1.
	_, err = st.CreateACL(ctx, CreateACLParams{
		CallerTokenID: tok.ID, AgentID: ag.ID, Username: "ok",
	})
	if err != nil {
		t.Fatalf("baseline CreateACL: %v", err)
	}
	versionBefore := readPolicyVersion(t, st.db, ag.ID)
	if versionBefore != 1 {
		t.Fatalf("baseline version = %d, want 1", versionBefore)
	}
	aclCountBefore := readACLCount(t, st.db, ag.ID)
	if aclCountBefore != 1 {
		t.Fatalf("baseline acl count = %d, want 1", aclCountBefore)
	}

	// Install a trigger that aborts any UPDATE on agent_policy_versions. This
	// makes the bumpPolicyVersionTx UPDATE statement (which sets the hash
	// after the upsert) fail deterministically. With the fix, the ACL insert
	// and the upsert+update are in the same tx and roll back together.
	if _, err := st.db.Exec(`
		CREATE TRIGGER fail_policy_update
		BEFORE UPDATE ON agent_policy_versions
		BEGIN
			SELECT RAISE(ABORT, 'simulated bump failure for #40 regression test');
		END;
	`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}

	// Second CreateACL: the bump's hash UPDATE will fail.
	_, err = st.CreateACL(ctx, CreateACLParams{
		CallerTokenID: tok.ID, AgentID: ag.ID, Username: "should-rollback",
	})
	if err == nil {
		t.Fatal("CreateACL succeeded despite simulated bump failure; tx not rolled back")
	}
	if !strings.Contains(err.Error(), "simulated") {
		t.Logf("error chain: %v (acceptable — what matters is the rollback)", err)
	}

	// The transactional contract: ACL row count must be unchanged (the insert
	// rolled back with the bump). Pre-fix, this would be 2 (insert leaked).
	if got := readACLCount(t, st.db, ag.ID); got != aclCountBefore {
		t.Errorf("ACL count after failed CreateACL = %d, want %d (insert leaked despite bump failure → tx not atomic)",
			got, aclCountBefore)
	}
	if got := readPolicyVersion(t, st.db, ag.ID); got != versionBefore {
		t.Errorf("policy version after failed CreateACL = %d, want %d (bump partially applied)",
			got, versionBefore)
	}

	// Symmetric check for DeleteACL: pick the surviving ACL row and try to
	// delete it. The bump UPDATE in DeleteACL also goes through the trigger.
	rows, err := st.db.QueryContext(ctx, `SELECT id FROM acl WHERE agent_id = ? LIMIT 1`, ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	var aclID string
	if rows.Next() {
		_ = rows.Scan(&aclID)
	}
	rows.Close()
	if aclID == "" {
		t.Fatal("no surviving ACL row to delete; setup error")
	}
	err = st.DeleteACL(ctx, aclID)
	if err == nil {
		t.Fatal("DeleteACL succeeded despite simulated bump failure; tx not rolled back")
	}
	if got := readACLCount(t, st.db, ag.ID); got != aclCountBefore {
		t.Errorf("ACL count after failed DeleteACL = %d, want %d (delete leaked despite bump failure → tx not atomic)",
			got, aclCountBefore)
	}
}

func readPolicyVersion(t *testing.T, db *sql.DB, agentID string) int64 {
	t.Helper()
	var v int64
	row := db.QueryRow(`SELECT version FROM agent_policy_versions WHERE agent_id = ?`, agentID)
	if err := row.Scan(&v); err != nil {
		return 0
	}
	return v
}

func readACLCount(t *testing.T, db *sql.DB, agentID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM acl WHERE agent_id = ?`, agentID).Scan(&n); err != nil {
		t.Fatalf("count acl: %v", err)
	}
	return n
}
