package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// makeAgentWithPrincipalsDir returns a minimal Agent with a principals dir
// set to a temp dir and a default logger.
func makeAgentWithPrincipalsDir(t *testing.T) (*Agent, string) {
	t.Helper()
	dir := t.TempDir()
	a := &Agent{
		cfg: Config{
			ExpectedPaths: ExpectedPaths{PrincipalsDir: dir},
		},
		logger: slog.Default(),
	}
	return a, dir
}

// TestApplyPolicy_WritesFile verifies that a valid policy snapshot writes a
// principals file containing the expected caller_token_ids.
func TestApplyPolicy_WritesFile(t *testing.T) {
	a, dir := makeAgentWithPrincipalsDir(t)

	snap := api.PolicyPayload{
		Version: 1,
		Hash:    "blake3:abc",
		Principals: []api.PolicyPrincipal{
			{Username: "derek", CallerTokenIDs: []string{"caller_abc", "caller_xyz"}},
		},
	}
	a.runApplyPolicy(snap)

	content, err := os.ReadFile(filepath.Join(dir, "derek"))
	if err != nil {
		t.Fatalf("principals file not written: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 || lines[0] != "caller_abc" || lines[1] != "caller_xyz" {
		t.Errorf("unexpected content: %q", content)
	}
}

// TestApplyPolicy_StateOKOnSuccess verifies that policyStateVal is updated after
// a successful apply.
func TestApplyPolicy_StateOKOnSuccess(t *testing.T) {
	a, _ := makeAgentWithPrincipalsDir(t)

	snap := api.PolicyPayload{
		Version: 3,
		Hash:    "blake3:def",
		Principals: []api.PolicyPrincipal{
			{Username: "alice", CallerTokenIDs: []string{"caller_one"}},
		},
	}
	a.runApplyPolicy(snap)

	a.policyMu.Lock()
	ps := a.policyStateVal
	a.policyMu.Unlock()

	if ps.appliedVersion != 3 {
		t.Errorf("appliedVersion = %d, want 3", ps.appliedVersion)
	}
	if ps.appliedHash != "blake3:def" {
		t.Errorf("appliedHash = %q, want blake3:def", ps.appliedHash)
	}
	if ps.lastApplyStatus != "ok" {
		t.Errorf("lastApplyStatus = %q, want ok", ps.lastApplyStatus)
	}
	if ps.lastApplyError != nil {
		t.Errorf("lastApplyError should be nil, got %q", *ps.lastApplyError)
	}
	if ps.lastApplyAt == 0 {
		t.Error("lastApplyAt should be non-zero")
	}
}

// TestApplyPolicy_RemovesStaleFile verifies that files for users removed from
// policy are deleted.
func TestApplyPolicy_RemovesStaleFile(t *testing.T) {
	a, dir := makeAgentWithPrincipalsDir(t)

	// Pre-create a stale file.
	stale := filepath.Join(dir, "old-user")
	if err := os.WriteFile(stale, []byte("caller_old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Apply policy without old-user.
	snap := api.PolicyPayload{
		Version: 2,
		Hash:    "blake3:xyz",
		Principals: []api.PolicyPrincipal{
			{Username: "derek", CallerTokenIDs: []string{"caller_new"}},
		},
	}
	a.runApplyPolicy(snap)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale principals file should be removed after policy apply")
	}
}

// TestApplyPolicy_EmptyPolicyWipesAllFiles verifies that an empty principals
// map deletes all existing principals files.
func TestApplyPolicy_EmptyPolicyWipesAllFiles(t *testing.T) {
	a, dir := makeAgentWithPrincipalsDir(t)

	// Pre-create two principals files.
	for _, user := range []string{"alice", "bob"} {
		_ = os.WriteFile(filepath.Join(dir, user), []byte("caller\n"), 0o644)
	}

	snap := api.PolicyPayload{
		Version:    3,
		Hash:       "",
		Principals: []api.PolicyPrincipal{},
	}
	a.runApplyPolicy(snap)

	for _, user := range []string{"alice", "bob"} {
		if _, err := os.Stat(filepath.Join(dir, user)); !os.IsNotExist(err) {
			t.Errorf("file for %s should be deleted after empty policy apply", user)
		}
	}
}

// TestApplyPolicy_FailOnDirPermission verifies that a permission error on the
// principals dir sets lastApplyStatus=failed and does NOT advance appliedVersion.
func TestApplyPolicy_FailOnDirPermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 not enforced on Windows")
	}

	a, dir := makeAgentWithPrincipalsDir(t)

	// Write a valid policy first so we have an initial version.
	snap1 := api.PolicyPayload{
		Version: 1, Hash: "blake3:first",
		Principals: []api.PolicyPrincipal{{Username: "u1", CallerTokenIDs: []string{"c1"}}},
	}
	a.runApplyPolicy(snap1)

	a.policyMu.Lock()
	version1 := a.policyStateVal.appliedVersion
	a.policyMu.Unlock()

	// Make dir unwritable.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	snap2 := api.PolicyPayload{
		Version: 2, Hash: "blake3:second",
		Principals: []api.PolicyPrincipal{{Username: "u2", CallerTokenIDs: []string{"c2"}}},
	}
	a.runApplyPolicy(snap2)

	// Restore perms before reading state.
	os.Chmod(dir, 0o755)

	a.policyMu.Lock()
	ps := a.policyStateVal
	a.policyMu.Unlock()

	if ps.appliedVersion != version1 {
		t.Errorf("appliedVersion advanced on failure: got %d, want %d", ps.appliedVersion, version1)
	}
	if ps.lastApplyStatus != "failed" {
		t.Errorf("lastApplyStatus = %q, want failed", ps.lastApplyStatus)
	}
	if ps.lastApplyError == nil {
		t.Error("lastApplyError should be set on failure")
	}
}

// TestApplyPolicy_MalformedCallerTokenRejected verifies that a caller_token_id
// containing a newline is rejected and no file is written.
func TestApplyPolicy_MalformedCallerTokenRejected(t *testing.T) {
	a, dir := makeAgentWithPrincipalsDir(t)

	snap := api.PolicyPayload{
		Version: 1,
		Hash:    "blake3:bad",
		Principals: []api.PolicyPrincipal{
			{Username: "alice", CallerTokenIDs: []string{"caller_ok", "bad\ncaller"}},
		},
	}
	a.runApplyPolicy(snap)

	// File should NOT be written.
	if _, err := os.Stat(filepath.Join(dir, "alice")); !os.IsNotExist(err) {
		t.Error("principals file should not be written for malformed caller_token_id")
	}

	a.policyMu.Lock()
	ps := a.policyStateVal
	a.policyMu.Unlock()

	if ps.lastApplyStatus != "failed" {
		t.Errorf("lastApplyStatus = %q, want failed", ps.lastApplyStatus)
	}
}

// TestApplyPolicy_AtomicWrite verifies that the temp file is renamed atomically.
// We check the principals file exists after apply and is not the .tmp file.
func TestApplyPolicy_AtomicWrite(t *testing.T) {
	a, dir := makeAgentWithPrincipalsDir(t)

	snap := api.PolicyPayload{
		Version: 1, Hash: "blake3:atom",
		Principals: []api.PolicyPrincipal{
			{Username: "carol", CallerTokenIDs: []string{"tok1"}},
		},
	}
	a.runApplyPolicy(snap)

	// Target file should exist.
	if _, err := os.Stat(filepath.Join(dir, "carol")); err != nil {
		t.Fatalf("principals file not found: %v", err)
	}
	// Temp file should not exist.
	if _, err := os.Stat(filepath.Join(dir, "carol.tmp")); !os.IsNotExist(err) {
		t.Error("tmp file should not remain after successful apply")
	}
}

// TestApplyPolicy_RecoveryAfterFailure verifies that restoring dir permissions
// allows the next apply to succeed.
func TestApplyPolicy_RecoveryAfterFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 not enforced on Windows")
	}

	a, dir := makeAgentWithPrincipalsDir(t)

	// Make dir unwritable → fail.
	os.Chmod(dir, 0o000)
	snap1 := api.PolicyPayload{Version: 1, Hash: "h1",
		Principals: []api.PolicyPrincipal{{Username: "u", CallerTokenIDs: []string{"c"}}}}
	a.runApplyPolicy(snap1)

	// Restore perms → next apply should succeed.
	os.Chmod(dir, 0o755)
	snap2 := api.PolicyPayload{Version: 2, Hash: "h2",
		Principals: []api.PolicyPrincipal{{Username: "u", CallerTokenIDs: []string{"c"}}}}
	a.runApplyPolicy(snap2)

	a.policyMu.Lock()
	ps := a.policyStateVal
	a.policyMu.Unlock()

	if ps.appliedVersion != 2 {
		t.Errorf("appliedVersion = %d after recovery, want 2", ps.appliedVersion)
	}
	if ps.lastApplyStatus != "ok" {
		t.Errorf("lastApplyStatus = %q after recovery, want ok", ps.lastApplyStatus)
	}
}

// TestValidateCallerTokenID verifies rejection of known-bad patterns.
func TestValidateCallerTokenID(t *testing.T) {
	bad := []string{
		"",
		"has space",
		"has\nnewline",
		"has\ttab",
		"has,comma",
		"has*glob",
		"has?glob",
		"has[bracket]",
	}
	for _, s := range bad {
		if err := validateCallerTokenID(s); err == nil {
			t.Errorf("expected error for %q, got nil", s)
		}
	}

	good := []string{
		"caller_abc123",
		"uct_caller_deadbeef_secret",
		"normal-token",
		"token.with.dots",
	}
	for _, s := range good {
		if err := validateCallerTokenID(s); err != nil {
			t.Errorf("unexpected error for %q: %v", s, err)
		}
	}
}

// TestApplyPolicy_LastApplyAtUpdated verifies that last_apply_at advances after apply.
func TestApplyPolicy_LastApplyAtUpdated(t *testing.T) {
	a, _ := makeAgentWithPrincipalsDir(t)

	before := time.Now().Unix()
	snap := api.PolicyPayload{
		Version:    1,
		Hash:       "h",
		Principals: []api.PolicyPrincipal{{Username: "x", CallerTokenIDs: []string{"c"}}},
	}
	a.runApplyPolicy(snap)

	a.policyMu.Lock()
	ts := a.policyStateVal.lastApplyAt
	a.policyMu.Unlock()

	if ts < before {
		t.Errorf("lastApplyAt = %d, expected >= %d", ts, before)
	}
}
