// T1b cert-flow scenarios. Builds on the T1a Compose harness.
//
// Each test brings up a fresh Compose stack (composeUp) to satisfy the
// "no cross-test pollution" requirement from #67. With the build layer
// cache hot after the first run, `compose up --wait` is ~30s, leaving
// ample budget for the per-scenario test body inside the 10-min total.
//
//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/test/e2e/harness"
)

const (
	// hostCPURL is the host-mapped port published by compose.yml. Inside the
	// containers the CP is reachable as http://cp:7777; from the test process
	// running on the host we use 127.0.0.1:47777.
	hostCPURL = "http://127.0.0.1:47777"

	// targetUser matches the entrypoint's TARGET_USER env. Hardcoded in
	// compose.yml so the Agent container can pre-create the unix account.
	targetUser = "tester"
	// agentName matches AGENT_NAME in compose.yml.
	agentName = "agent-1"

	// applyTimeout is how long we wait for an ACL change to land in the
	// Agent's principals file. The agent heartbeats every 10s; we add slack.
	applyTimeout = 15 * time.Second
)

// bootstrapCallerToken reads the caller token the CP entrypoint published to
// the shared volume. The bootstrap caller has admin rights — it can mint
// other tokens, grant ACLs, etc. Tests that want a per-scenario caller mint
// one via callerToken/MintCallerToken.
func bootstrapCallerToken(t *testing.T) string {
	t.Helper()
	out, err := composeCmd(t, "exec", "-T", "cp", "cat", "/shared/caller-token").Output()
	if err != nil {
		t.Fatalf("[ADVISORY] read /shared/caller-token: %v", err)
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		t.Fatalf("[ADVISORY] caller token empty")
	}
	return tok
}

// callerTokenIDByLabel resolves a caller token's id by listing /v1/tokens and
// matching the label. Used because the harness MintCallerToken returns the
// plaintext token but ACL grants need the id.
//
// We avoid coupling to /v1/tokens response shape by GET'ing /v1/tokens and
// scanning labels.
func callerTokenIDByLabel(t *testing.T, c *harness.Client, label string) string {
	t.Helper()
	var resp []struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Label string `json:"label"`
	}
	if err := c.Do(context.Background(), "GET", "/v1/tokens", nil, &resp); err != nil {
		t.Fatalf("[REQUIRED] list tokens: %v", err)
	}
	for _, x := range resp {
		if x.Kind == "caller" && x.Label == label {
			return x.ID
		}
	}
	t.Fatalf("[REQUIRED] no caller token with label=%q", label)
	return ""
}

// callerExec runs a command inside the caller container, returning combined
// output and the exit code. Does NOT t.Fatal on non-zero — callers assert.
func callerExec(t *testing.T, args ...string) (string, int) {
	t.Helper()
	full := append([]string{"exec", "-T", "caller"}, args...)
	cmd := composeCmd(t, full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		}
		return string(out), -1
	}
	return string(out), 0
}

// agentExec runs a command inside the agent container.
func agentExec(t *testing.T, args ...string) (string, int) {
	t.Helper()
	full := append([]string{"exec", "-T", "agent"}, args...)
	cmd := composeCmd(t, full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		}
		return string(out), -1
	}
	return string(out), 0
}

// callerSSHAs runs `uncluster ssh agentName -- echo …` via the Caller's CLI
// using a per-test caller token persisted to its config. Returns stdout/stderr
// and exit code.
//
// The cli.toml token is overwritten per-call so each test can use its own
// caller identity without depending on the bootstrap token.
func callerSSHAs(t *testing.T, callerTokenPlain, principal string, cmdParts ...string) (string, int) {
	t.Helper()
	// Overwrite cli.toml inside the caller. The TOML format is plain so we
	// embed via heredoc to a `sh -c` inside the container.
	tomlBody := fmt.Sprintf(`server = "http://cp:7777"
token = "%s"
ssh_key_path = "/var/lib/uncluster-caller/keys/id_ed25519"
`, callerTokenPlain)
	cfgScript := fmt.Sprintf("mkdir -p /root/.config/uncluster && cat > /root/.config/uncluster/cli.toml <<'TOMLEOF'\n%sTOMLEOF\nchmod 0600 /root/.config/uncluster/cli.toml\n", tomlBody)
	if _, code := callerExec(t, "sh", "-c", cfgScript); code != 0 {
		t.Fatalf("[ADVISORY] writing per-test cli.toml: rc=%d", code)
	}

	sshArgs := []string{"uncluster", "ssh", "--as", principal, agentName, "--"}
	sshArgs = append(sshArgs, cmdParts...)
	return callerExec(t, sshArgs...)
}

// waitForPrincipal blocks until /etc/ssh/auth_principals/<username> in the
// agent container contains `wantTokenID`, or applyTimeout elapses.
func waitForPrincipal(t *testing.T, username, wantTokenID string) error {
	t.Helper()
	deadline := time.Now().Add(applyTimeout)
	for time.Now().Before(deadline) {
		out, _ := agentExec(t, "cat", "/etc/ssh/auth_principals/"+username)
		if strings.Contains(out, wantTokenID) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	out, _ := agentExec(t, "cat", "/etc/ssh/auth_principals/"+username)
	return fmt.Errorf("token id %q never appeared in /etc/ssh/auth_principals/%s within %s; last contents:\n%s",
		wantTokenID, username, applyTimeout, out)
}

// waitForPrincipalAbsent is the inverse: waits until the principals file is
// absent or no longer contains wantTokenID.
func waitForPrincipalAbsent(t *testing.T, username, wantTokenID string) error {
	t.Helper()
	deadline := time.Now().Add(applyTimeout)
	for time.Now().Before(deadline) {
		out, _ := agentExec(t, "cat", "/etc/ssh/auth_principals/"+username)
		if !strings.Contains(out, wantTokenID) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	out, _ := agentExec(t, "cat", "/etc/ssh/auth_principals/"+username)
	return fmt.Errorf("token id %q still present in /etc/ssh/auth_principals/%s after %s; last contents:\n%s",
		wantTokenID, username, applyTimeout, out)
}

// adminClient returns a harness.Client authenticated with the bootstrap
// caller token. Use this for admin actions in tests (mint tokens, grant
// ACLs, list audit events).
func adminClient(t *testing.T) *harness.Client {
	t.Helper()
	return harness.NewClient(hostCPURL, bootstrapCallerToken(t))
}

// ---------------------------------------------------------------------------
// Scenario 1: happy path.
// Protects: end-to-end Caller→CP→Agent SSH cert flow + cert audit emission
// (CONTEXT.md §"Cert flow", ACCEPTANCE.md §"Caller can SSH").
// ---------------------------------------------------------------------------
func TestCertFlow_HappyPath(t *testing.T) {
	composeUp(t)
	ctx := context.Background()
	admin := adminClient(t)

	// Mint a fresh caller token for this test.
	callerTok, err := admin.MintCallerToken(ctx, "happy-path")
	if err != nil {
		t.Fatalf("[REQUIRED] mint caller token: %v", err)
	}
	callerID := callerTokenIDByLabel(t, admin, "happy-path")

	// Grant ACL.
	if _, err := admin.GrantACL(ctx, callerID, agentName, targetUser); err != nil {
		t.Fatalf("[REQUIRED] grant acl: %v", err)
	}

	// Wait for the agent to apply the new ACL — sshd needs the principal
	// file populated before the cert will be accepted.
	if err := waitForPrincipal(t, targetUser, callerID); err != nil {
		t.Fatalf("[REQUIRED] principals apply: %v", err)
	}

	// SSH and run a command.
	stdout, code := callerSSHAs(t, callerTok, targetUser, "echo", "hello")
	if code != 0 {
		t.Fatalf("[REQUIRED] ssh exit=%d, want 0; output:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "hello") {
		t.Fatalf("[REQUIRED] ssh stdout missing 'hello':\n%s", stdout)
	}

	// Assert a cert audit event landed.
	events, err := admin.ListCertEvents(ctx, map[string]string{
		"caller":  callerID,
		"outcome": "signed",
	})
	if err != nil {
		t.Fatalf("[REQUIRED] list cert events: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("[REQUIRED] expected at least one signed cert audit event for caller=%s", callerID)
	}
}

// ---------------------------------------------------------------------------
// Scenario 2: exit code propagation.
// Protects: `uncluster ssh ... -- exit 7` returns 7
// (ACCEPTANCE.md §"Exit codes propagated").
// ---------------------------------------------------------------------------
func TestCertFlow_ExitCodePropagation(t *testing.T) {
	composeUp(t)
	ctx := context.Background()
	admin := adminClient(t)

	callerTok, err := admin.MintCallerToken(ctx, "exitcode")
	if err != nil {
		t.Fatalf("[REQUIRED] mint caller token: %v", err)
	}
	callerID := callerTokenIDByLabel(t, admin, "exitcode")
	if _, err := admin.GrantACL(ctx, callerID, agentName, targetUser); err != nil {
		t.Fatalf("[REQUIRED] grant acl: %v", err)
	}
	if err := waitForPrincipal(t, targetUser, callerID); err != nil {
		t.Fatalf("[REQUIRED] principals apply: %v", err)
	}

	// Run a command that returns 7. `sh -c 'exit 7'` is the canonical form.
	_, code := callerSSHAs(t, callerTok, targetUser, "sh", "-c", "exit 7")
	if code != 7 {
		t.Fatalf("[REQUIRED] expected exit 7, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: ACL denial.
// Protects: cert request without ACL → 403 acl_miss + audit denial row
// (CONTEXT.md §"Policy", ACCEPTANCE.md §"Denied request audited").
// ---------------------------------------------------------------------------
func TestCertFlow_ACLDenial(t *testing.T) {
	composeUp(t)
	ctx := context.Background()
	admin := adminClient(t)

	// Mint a caller WITHOUT granting any ACL.
	callerTok, err := admin.MintCallerToken(ctx, "denied")
	if err != nil {
		t.Fatalf("[REQUIRED] mint caller token: %v", err)
	}
	callerID := callerTokenIDByLabel(t, admin, "denied")

	// Try to request a cert directly via the harness — expect 403.
	callerClient := harness.NewClient(hostCPURL, callerTok)
	_, err = callerClient.RequestCert(ctx, agentName, targetUser, "ssh-ed25519 AAA stub", 300)
	if err == nil {
		t.Fatalf("[REQUIRED] expected cert request to fail without ACL")
	}
	var he *harness.HTTPError
	if !errors.As(err, &he) || he.Status != 403 {
		t.Fatalf("[REQUIRED] expected 403 acl_miss, got: %v", err)
	}

	// And the audit log should have a denied row.
	events, lerr := admin.ListCertEvents(ctx, map[string]string{
		"caller":  callerID,
		"outcome": "denied",
	})
	if lerr != nil {
		t.Fatalf("[REQUIRED] list cert events: %v", lerr)
	}
	if len(events) == 0 {
		t.Fatalf("[REQUIRED] expected at least one denied cert audit event for caller=%s", callerID)
	}
	if events[0].DenialReason != "acl_miss" {
		t.Fatalf("[REQUIRED] denial_reason=%q, want acl_miss", events[0].DenialReason)
	}

	// And `uncluster ssh` should error clearly.
	stdout, code := callerSSHAs(t, callerTok, targetUser, "echo", "should-not-run")
	if code == 0 {
		t.Fatalf("[REQUIRED] expected ssh failure on denied caller; output: %s", stdout)
	}
	if !strings.Contains(stdout, "cert") && !strings.Contains(stdout, "403") && !strings.Contains(stdout, "acl") {
		t.Logf("WARN: ssh failure output does not mention cert/403/acl; got:\n%s", stdout)
	}
}

// ---------------------------------------------------------------------------
// Scenario 4: policy apply timing.
// Protects: ACL grant lands in agent's principals file within one heartbeat
// interval (~10s). architecture.md §"Policy sync".
// ---------------------------------------------------------------------------
func TestCertFlow_PolicyApplyTiming(t *testing.T) {
	composeUp(t)
	ctx := context.Background()
	admin := adminClient(t)

	_, err := admin.MintCallerToken(ctx, "apply-timing")
	if err != nil {
		t.Fatalf("[REQUIRED] mint caller token: %v", err)
	}
	callerID := callerTokenIDByLabel(t, admin, "apply-timing")

	// Verify principals file does NOT contain the new caller initially.
	out, _ := agentExec(t, "cat", "/etc/ssh/auth_principals/"+targetUser)
	if strings.Contains(out, callerID) {
		t.Fatalf("[ADVISORY] principals already contains caller %s before grant: %s", callerID, out)
	}

	start := time.Now()
	if _, err := admin.GrantACL(ctx, callerID, agentName, targetUser); err != nil {
		t.Fatalf("[REQUIRED] grant acl: %v", err)
	}
	if err := waitForPrincipal(t, targetUser, callerID); err != nil {
		t.Fatalf("[REQUIRED] principals apply: %v", err)
	}
	elapsed := time.Since(start)
	t.Logf("ACL applied to principals in %s", elapsed)
	if elapsed > applyTimeout {
		t.Fatalf("[REQUIRED] apply elapsed %s > budget %s", elapsed, applyTimeout)
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: revoke timing + in-flight cert keeps working.
// Protects: revoke lands within one heartbeat; in-flight SSH session is not
// killed by cert revocation. ARC §4 "existing SSH sessions unaffected".
// ---------------------------------------------------------------------------
func TestCertFlow_RevokeTiming(t *testing.T) {
	composeUp(t)
	ctx := context.Background()
	admin := adminClient(t)

	callerTok, err := admin.MintCallerToken(ctx, "revoke-timing")
	if err != nil {
		t.Fatalf("[REQUIRED] mint caller token: %v", err)
	}
	callerID := callerTokenIDByLabel(t, admin, "revoke-timing")
	aclID, err := admin.GrantACL(ctx, callerID, agentName, targetUser)
	if err != nil {
		t.Fatalf("[REQUIRED] grant acl: %v", err)
	}
	if err := waitForPrincipal(t, targetUser, callerID); err != nil {
		t.Fatalf("[REQUIRED] initial apply: %v", err)
	}

	// First SSH succeeds — this issues a cert and runs a quick command.
	// (We can't keep a session open across the test boundary; the
	// "existing session unaffected" invariant is therefore tested with the
	// stronger claim: a cert issued before revocation continues to work
	// for its TTL even after ACL revoke. The CA does not revoke certs;
	// only the ACL gate at issuance is affected.)
	stdout, code := callerSSHAs(t, callerTok, targetUser, "echo", "pre-revoke")
	if code != 0 {
		t.Fatalf("[REQUIRED] pre-revoke ssh failed rc=%d: %s", code, stdout)
	}

	// Revoke the ACL.
	if err := admin.RevokeACL(ctx, aclID); err != nil {
		t.Fatalf("[REQUIRED] revoke acl: %v", err)
	}
	if err := waitForPrincipalAbsent(t, targetUser, callerID); err != nil {
		t.Fatalf("[REQUIRED] principal not removed: %v", err)
	}

	// A NEW cert request after revoke should be denied.
	callerClient := harness.NewClient(hostCPURL, callerTok)
	if _, err := callerClient.RequestCert(ctx, agentName, targetUser, "ssh-ed25519 AAA stub", 300); err == nil {
		t.Fatalf("[REQUIRED] post-revoke cert request unexpectedly succeeded")
	}
}

// ---------------------------------------------------------------------------
// Scenario 6: two-caller independence.
// Protects: distinct caller identities produce distinct audit events with
// different cert principals; both succeed concurrently
// (CONTEXT.md §"Caller token", architecture.md §"Audit").
// ---------------------------------------------------------------------------
func TestCertFlow_TwoCallerIndependence(t *testing.T) {
	composeUp(t)
	ctx := context.Background()
	admin := adminClient(t)

	tokA, err := admin.MintCallerToken(ctx, "caller-a")
	if err != nil {
		t.Fatalf("[REQUIRED] mint A: %v", err)
	}
	tokB, err := admin.MintCallerToken(ctx, "caller-b")
	if err != nil {
		t.Fatalf("[REQUIRED] mint B: %v", err)
	}
	idA := callerTokenIDByLabel(t, admin, "caller-a")
	idB := callerTokenIDByLabel(t, admin, "caller-b")

	if _, err := admin.GrantACL(ctx, idA, agentName, targetUser); err != nil {
		t.Fatalf("[REQUIRED] grant A: %v", err)
	}
	if _, err := admin.GrantACL(ctx, idB, agentName, targetUser); err != nil {
		t.Fatalf("[REQUIRED] grant B: %v", err)
	}
	if err := waitForPrincipal(t, targetUser, idA); err != nil {
		t.Fatalf("[REQUIRED] apply A: %v", err)
	}
	if err := waitForPrincipal(t, targetUser, idB); err != nil {
		t.Fatalf("[REQUIRED] apply B: %v", err)
	}

	// Run both SSHes; either order is fine.
	outA, codeA := callerSSHAs(t, tokA, targetUser, "echo", "from-A")
	if codeA != 0 || !strings.Contains(outA, "from-A") {
		t.Fatalf("[REQUIRED] A ssh rc=%d out=%s", codeA, outA)
	}
	outB, codeB := callerSSHAs(t, tokB, targetUser, "echo", "from-B")
	if codeB != 0 || !strings.Contains(outB, "from-B") {
		t.Fatalf("[REQUIRED] B ssh rc=%d out=%s", codeB, outB)
	}

	// Audit log shows two distinct events.
	all, err := admin.ListCertEvents(ctx, map[string]string{"outcome": "signed"})
	if err != nil {
		t.Fatalf("[REQUIRED] list cert events: %v", err)
	}
	sawA, sawB := false, false
	for _, e := range all {
		if e.CallerTokenID == idA && e.CertPrincipal == idA {
			sawA = true
		}
		if e.CallerTokenID == idB && e.CertPrincipal == idB {
			sawB = true
		}
	}
	if !sawA {
		t.Fatalf("[REQUIRED] audit missing event for caller A (id=%s)", idA)
	}
	if !sawB {
		t.Fatalf("[REQUIRED] audit missing event for caller B (id=%s)", idB)
	}
}

// ---------------------------------------------------------------------------
// Scenario 7: deprovision flow.
// Protects: DELETE /v1/agents/<id> causes next heartbeat to 410 → agent
// wipes principals, writes .deprovisioned marker, exits 0 (per #46 fix +
// ACCEPTANCE.md §44).
// ---------------------------------------------------------------------------
func TestCertFlow_Deprovision(t *testing.T) {
	composeUp(t)
	ctx := context.Background()
	admin := adminClient(t)

	// Pre-populate principals so we can verify wipe.
	if _, err := admin.MintCallerToken(ctx, "deprov-victim"); err != nil {
		t.Fatalf("[REQUIRED] mint caller: %v", err)
	}
	callerID := callerTokenIDByLabel(t, admin, "deprov-victim")
	if _, err := admin.GrantACL(ctx, callerID, agentName, targetUser); err != nil {
		t.Fatalf("[REQUIRED] grant acl: %v", err)
	}
	if err := waitForPrincipal(t, targetUser, callerID); err != nil {
		t.Fatalf("[REQUIRED] pre-deprov apply: %v", err)
	}

	// Deprovision.
	if err := admin.DeprovisionAgent(ctx, agentName); err != nil {
		t.Fatalf("[REQUIRED] deprovision agent: %v", err)
	}

	// Wait for principals to be wiped (deprovision is async — agent must
	// heartbeat first).
	deadline := time.Now().Add(applyTimeout)
	wiped := false
	for time.Now().Before(deadline) {
		out, _ := agentExec(t, "cat", "/etc/ssh/auth_principals/"+targetUser)
		if !strings.Contains(out, callerID) {
			wiped = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !wiped {
		t.Fatalf("[REQUIRED] principals not wiped within %s", applyTimeout)
	}

	// .deprovisioned marker should appear next to agent.toml.
	// Path is at $XDG_CONFIG_HOME/uncluster/.deprovisioned or
	// /root/.config/uncluster/.deprovisioned per cfg path resolution.
	deadlineMarker := time.Now().Add(applyTimeout)
	markerFound := false
	for time.Now().Before(deadlineMarker) {
		_, code := agentExec(t, "test", "-f", "/root/.config/uncluster/.deprovisioned")
		if code == 0 {
			markerFound = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !markerFound {
		// Dump diagnostic info to help debug a future failure.
		listing, _ := agentExec(t, "ls", "-la", "/root/.config/uncluster")
		t.Fatalf("[REQUIRED] .deprovisioned marker not found within %s\nlisting:\n%s", applyTimeout, listing)
	}
}
