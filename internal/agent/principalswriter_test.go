package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// TestDesiredStateRoundTrip verifies the agent→writer desired-state shape
// survives marshal/unmarshal intact. The writer reads this off the spool as
// untrusted bytes, so the encoding must be stable and lossless (#127).
func TestDesiredStateRoundTrip(t *testing.T) {
	snap := api.PolicyPayload{
		Version: 7,
		Hash:    "blake3:cafe",
		Principals: []api.PolicyPrincipal{
			{Username: "derek", CallerTokenIDs: []string{"caller_abc", "caller_xyz"}},
			{Username: "root", CallerTokenIDs: []string{"caller_ops"}},
		},
	}
	d := desiredStateFromPayload(snap)
	b, err := marshalDesiredState(d)
	if err != nil {
		t.Fatalf("marshalDesiredState: %v", err)
	}
	got, err := unmarshalDesiredState(b)
	if err != nil {
		t.Fatalf("unmarshalDesiredState: %v", err)
	}
	if got.Version != 7 || got.Hash != "blake3:cafe" {
		t.Errorf("version/hash = %d/%q, want 7/blake3:cafe", got.Version, got.Hash)
	}
	pl := got.toPayload()
	if len(pl.Principals) != 2 {
		t.Fatalf("principals len = %d, want 2", len(pl.Principals))
	}
	if pl.Principals[0].Username != "derek" || len(pl.Principals[0].CallerTokenIDs) != 2 {
		t.Errorf("principal[0] = %+v", pl.Principals[0])
	}
}

// TestUnmarshalDesiredState_GarbageRejected verifies malformed spool bytes are
// reported as an error (→ failed apply) and never panic. The writer treats the
// spool as untrusted (#127).
func TestUnmarshalDesiredState_GarbageRejected(t *testing.T) {
	if _, err := unmarshalDesiredState([]byte("{not json")); err == nil {
		t.Error("expected error for malformed desired-state, got nil")
	}
}

// TestAppliedStatusMatchesDesired verifies the agent only accepts an
// applied-status whose version AND hash match what it submitted — so a stale
// applied.json from a prior round-trip does not falsely resolve the current
// apply (#127 acceptance: never a silent wrong-version success).
func TestAppliedStatusMatchesDesired(t *testing.T) {
	d := desiredState{Version: 5, Hash: "blake3:beef"}

	tests := []struct {
		name string
		s    appliedStatus
		want bool
	}{
		{"exact match", appliedStatus{AppliedVersion: 5, AppliedHash: "blake3:beef", Status: "ok"}, true},
		{"stale version", appliedStatus{AppliedVersion: 4, AppliedHash: "blake3:beef", Status: "ok"}, false},
		{"stale hash", appliedStatus{AppliedVersion: 5, AppliedHash: "blake3:old", Status: "ok"}, false},
		{"both stale", appliedStatus{AppliedVersion: 1, AppliedHash: "x", Status: "ok"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.matchesDesired(d); got != tc.want {
				t.Errorf("matchesDesired = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAppliedStatusRoundTrip verifies the writer→agent applied-status shape
// survives marshal/unmarshal including the failure error string.
func TestAppliedStatusRoundTrip(t *testing.T) {
	s := appliedStatus{AppliedVersion: 9, AppliedHash: "h", Status: "failed", Error: "boom"}
	b, err := marshalAppliedStatus(s)
	if err != nil {
		t.Fatalf("marshalAppliedStatus: %v", err)
	}
	got, err := unmarshalAppliedStatus(b)
	if err != nil {
		t.Fatalf("unmarshalAppliedStatus: %v", err)
	}
	if got != s {
		t.Errorf("round-trip = %+v, want %+v", got, s)
	}
}

// TestDesiredStateDigestChangesWithContent verifies the digest distinguishes
// distinct desired-states (so the writer re-renders) and is stable for equal
// bytes (so it does not re-render an unchanged spool on every poll).
func TestDesiredStateDigestChangesWithContent(t *testing.T) {
	a, _ := marshalDesiredState(desiredState{Version: 1, Hash: "h1"})
	b, _ := marshalDesiredState(desiredState{Version: 1, Hash: "h2"})
	if desiredStateDigest(a) == desiredStateDigest(b) {
		t.Error("digest collided for distinct desired-states")
	}
	if desiredStateDigest(a) != desiredStateDigest(a) {
		t.Error("digest not stable for identical bytes")
	}
}

// TestValidatePolicyPayload_RejectsTraversal verifies the writer-side
// re-validation rejects a path-traversal username and a path-escaping
// caller_token_id — the compromised-agent simulation in the #127 acceptance
// criteria. This is the same validator the writer runs on untrusted spool
// input before rendering any file.
func TestValidatePolicyPayload_RejectsTraversal(t *testing.T) {
	bad := []api.PolicyPayload{
		{Principals: []api.PolicyPrincipal{{Username: "../evil", CallerTokenIDs: []string{"c"}}}},
		{Principals: []api.PolicyPrincipal{{Username: "..\\evil", CallerTokenIDs: []string{"c"}}}},
		{Principals: []api.PolicyPrincipal{{Username: "ok", CallerTokenIDs: []string{"bad\ninjection"}}}},
		{Principals: []api.PolicyPrincipal{{Username: "ok", CallerTokenIDs: []string{"glob*"}}}},
		{Principals: []api.PolicyPrincipal{{Username: "a/b", CallerTokenIDs: []string{"c"}}}},
	}
	for i, p := range bad {
		if err := validatePolicyPayload(p); err == nil {
			t.Errorf("case %d: expected validation error, got nil for %+v", i, p.Principals)
		}
	}

	good := api.PolicyPayload{Principals: []api.PolicyPrincipal{
		{Username: "derek", CallerTokenIDs: []string{"caller_abc123"}},
	}}
	if err := validatePolicyPayload(good); err != nil {
		t.Errorf("unexpected error for valid payload: %v", err)
	}
}

// TestApplyDesiredStateBytes_HappyPath exercises the writer's full core on a
// valid desired-state: it renders the per-user file and reports an "ok" status
// matching the submitted version+hash. This is the same code path the Windows
// writer service runs, so the round-trip is covered on the CI Linux host (where
// restrictPrincipalsFileACL is a no-op).
func TestApplyDesiredStateBytes_HappyPath(t *testing.T) {
	dir := t.TempDir()
	d := desiredState{
		Version: 4, Hash: "blake3:abc",
		Principals: []api.PolicyPrincipal{
			{Username: "derek", CallerTokenIDs: []string{"caller_a", "caller_b"}},
		},
	}
	b, err := marshalDesiredState(d)
	if err != nil {
		t.Fatal(err)
	}

	st := applyDesiredStateBytes(dir, b)
	if st.Status != "ok" {
		t.Fatalf("status = %q (err=%q), want ok", st.Status, st.Error)
	}
	if st.AppliedVersion != 4 || st.AppliedHash != "blake3:abc" {
		t.Errorf("applied version/hash = %d/%q, want 4/blake3:abc", st.AppliedVersion, st.AppliedHash)
	}
	got, err := os.ReadFile(filepath.Join(dir, "derek"))
	if err != nil {
		t.Fatalf("principals file not rendered: %v", err)
	}
	if string(got) != "caller_a\ncaller_b\n" {
		t.Errorf("content = %q", got)
	}
}

// TestApplyDesiredStateBytes_CompromisedAgentTraversalRejected is the #127
// compromised-agent simulation: a desired-state whose username escapes the
// principals dir must be REJECTED by the writer core and NEVER written. This is
// the load-bearing security property — the writer re-validates everything off
// the (untrusted) spool, so even if a compromised agent crafts a traversal
// username, no file is created outside (or inside) auth_principals for it.
func TestApplyDesiredStateBytes_CompromisedAgentTraversalRejected(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name string
		d    desiredState
	}{
		{
			name: "traversal username",
			d: desiredState{Version: 1, Hash: "h", Principals: []api.PolicyPrincipal{
				{Username: "..\\..\\evil", CallerTokenIDs: []string{"caller_x"}},
			}},
		},
		{
			name: "slash username",
			d: desiredState{Version: 1, Hash: "h", Principals: []api.PolicyPrincipal{
				{Username: "sub/evil", CallerTokenIDs: []string{"caller_x"}},
			}},
		},
		{
			name: "newline-injecting caller token",
			d: desiredState{Version: 1, Hash: "h", Principals: []api.PolicyPrincipal{
				{Username: "derek", CallerTokenIDs: []string{"ok\nroot"}},
			}},
		},
		{
			name: "glob caller token",
			d: desiredState{Version: 1, Hash: "h", Principals: []api.PolicyPrincipal{
				{Username: "derek", CallerTokenIDs: []string{"caller_*"}},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := marshalDesiredState(tc.d)
			if err != nil {
				t.Fatal(err)
			}
			st := applyDesiredStateBytes(dir, b)
			if st.Status != "failed" {
				t.Errorf("status = %q, want failed (writer must reject untrusted desired-state)", st.Status)
			}
			if st.Error == "" {
				t.Error("failed status must carry an error explaining the rejection")
			}
			// No file should have been created for the rejected username (the
			// rejected user in cases is "derek" in the token-injection cases too,
			// because validation runs before any write).
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				t.Errorf("writer created file %q for a rejected desired-state — must write nothing", e.Name())
			}
		})
	}

	// The dir must contain no escaped file anywhere up the tree either.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); err == nil {
		t.Error("traversal escaped the principals dir — a file named 'evil' was created in the parent")
	}
}

// TestApplyDesiredStateBytes_MalformedBytesFailed verifies garbage spool bytes
// yield a failed status (never a panic), so the agent's poll times out as a
// visible failure rather than the writer silently doing nothing.
func TestApplyDesiredStateBytes_MalformedBytesFailed(t *testing.T) {
	st := applyDesiredStateBytes(t.TempDir(), []byte("{garbage"))
	if st.Status != "failed" {
		t.Errorf("status = %q, want failed", st.Status)
	}
}

// TestApplyDesiredStateBytes_RewriteSemantics verifies the writer's apply is a
// full rewrite: a user dropped from a later desired-state has its file deleted
// (matching the architecture's "apply is rewrite, not merge" invariant).
func TestApplyDesiredStateBytes_RewriteSemantics(t *testing.T) {
	dir := t.TempDir()

	b1, _ := marshalDesiredState(desiredState{Version: 1, Hash: "h1", Principals: []api.PolicyPrincipal{
		{Username: "alice", CallerTokenIDs: []string{"caller_a"}},
		{Username: "bob", CallerTokenIDs: []string{"caller_b"}},
	}})
	if st := applyDesiredStateBytes(dir, b1); st.Status != "ok" {
		t.Fatalf("first apply failed: %q", st.Error)
	}

	// Second desired-state drops bob.
	b2, _ := marshalDesiredState(desiredState{Version: 2, Hash: "h2", Principals: []api.PolicyPrincipal{
		{Username: "alice", CallerTokenIDs: []string{"caller_a"}},
	}})
	if st := applyDesiredStateBytes(dir, b2); st.Status != "ok" {
		t.Fatalf("second apply failed: %q", st.Error)
	}
	if _, err := os.Stat(filepath.Join(dir, "bob")); !os.IsNotExist(err) {
		t.Error("bob's principals file should be deleted after a rewrite that drops him")
	}
	if _, err := os.Stat(filepath.Join(dir, "alice")); err != nil {
		t.Errorf("alice's principals file should remain: %v", err)
	}
}
