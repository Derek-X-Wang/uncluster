//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// pollPrincipal polls the agent's per-user principals file until its presence of
// wantTokenID equals `want`, or `budget` elapses. Like waitForPrincipal, but with
// a caller-supplied deadline: the fail-closed wipe is driven by the Agent's 30s
// ticker, and while the Control plane is paused an in-flight heartbeat blocks up
// to the 45s HTTP timeout before the ticker can fire — so the default 15s
// applyTimeout is far too short for the wipe.
func pollPrincipal(t *testing.T, username, wantTokenID string, want bool, budget time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		out, _ := agentExec(t, "cat", "/etc/ssh/auth_principals/"+username)
		if strings.Contains(out, wantTokenID) == want {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	out, _ := agentExec(t, "cat", "/etc/ssh/auth_principals/"+username)
	return fmt.Errorf("principal %q present=%v not reached within %s; last file contents:\n%s",
		wantTokenID, want, budget, out)
}

// TestCertFlow_FailClosedAfter proves the fail-closed-after threat-model row
// end-to-end: an Agent configured with a short fail-closed-after wipes its
// principals (deny-all) once it has been offline from the Control plane past the
// threshold, and re-applies Policy (the principals return) on reconnect.
//
// The partition is a `docker compose pause` of the CP container, NOT stop/start:
// the CP entrypoint re-runs `uncluster server bootstrap` on every start, which
// would re-mint the CA/tokens and break the Agent's registration. Pause freezes
// the process (cgroup freezer) with all state — CA, DB, ACLs, registration —
// intact, which is exactly a network partition followed by reconnect.
func TestCertFlow_FailClosedAfter(t *testing.T) {
	composeUp(t)
	ctx := context.Background()
	admin := adminClient(t)

	// 1. Configure a SHORT fail-closed-after on the Agent (server-side; the Agent
	// adopts it on its next heartbeat). PATCH /v1/agents/{name} takes seconds.
	const fcaSecs = 5
	if err := admin.Do(ctx, "PATCH", "/v1/agents/"+agentName,
		map[string]any{"fail_closed_after": fcaSecs}, nil); err != nil {
		t.Fatalf("[REQUIRED] set fail_closed_after: %v", err)
	}

	// 2. Mint a Caller and grant it an ACL row for the target user.
	if _, err := admin.MintCallerToken(ctx, "fail-closed"); err != nil {
		t.Fatalf("[REQUIRED] mint caller token: %v", err)
	}
	callerID := callerTokenIDByLabel(t, admin, "fail-closed")
	if _, err := admin.GrantACL(ctx, callerID, agentName, targetUser); err != nil {
		t.Fatalf("[REQUIRED] grant acl: %v", err)
	}

	// 3. Assert the principal is PRESENT. Reaching here also proves a post-PATCH
	// heartbeat happened (the same beat that applied the policy delivered the
	// fail_closed_after value), so the Agent has adopted the threshold.
	if err := waitForPrincipal(t, targetUser, callerID); err != nil {
		t.Fatalf("[REQUIRED] principal never applied before partition: %v", err)
	}

	// 4. SEVER Agent->Control-plane connectivity (freeze the CP).
	if out, err := composeCmd(t, "pause", "cp").CombinedOutput(); err != nil {
		t.Fatalf("[ADVISORY] pause cp: %v\n%s", err, out)
	}
	// Always thaw the CP before teardown, even if an assertion below fails.
	// (unpause on an already-running container is a harmless best-effort no-op.)
	t.Cleanup(func() { _ = composeCmd(t, "unpause", "cp").Run() })

	// 5. Assert principals get WIPED (deny-all) while offline past the threshold.
	// Budget = threshold(5s) + heartbeat HTTP timeout(<=45s, pause artifact) +
	// fail-closed ticker(<=30s) + slack.
	if err := pollPrincipal(t, targetUser, callerID, false, 100*time.Second); err != nil {
		t.Fatalf("[REQUIRED] principals NOT wiped after CP offline > %ds: %v", fcaSecs, err)
	}

	// 6. RESTORE connectivity.
	if out, err := composeCmd(t, "unpause", "cp").CombinedOutput(); err != nil {
		t.Fatalf("[ADVISORY] unpause cp: %v\n%s", err, out)
	}

	// 7. Assert Policy re-applies and the principal RETURNS. The wipe reset the
	// Agent's applied hash to empty, so the server's next heartbeat diff
	// re-delivers the full policy automatically — no manual re-grant.
	if err := pollPrincipal(t, targetUser, callerID, true, 30*time.Second); err != nil {
		t.Fatalf("[REQUIRED] principals did NOT re-apply after reconnect: %v", err)
	}
}
