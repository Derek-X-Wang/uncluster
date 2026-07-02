package policyhash

import (
	"encoding/hex"
	"testing"

	"lukechampine.com/blake3"
)

// TestCanonical_Golden locks the exact byte format behind ADR-0007's version
// handshake: one "username:caller\n" line PER GRANT, sorted by (username,
// caller) — NOT a grouped "username:caller1,caller2" line. A change here changes
// every existing Agent's policy hash and forces spurious version churn, so the
// bytes are pinned exactly.
func TestCanonical_Golden(t *testing.T) {
	grants := []Grant{
		{Username: "derek", CallerTokenID: "caller_b"},
		{Username: "alice", CallerTokenID: "caller_z"},
		{Username: "derek", CallerTokenID: "caller_a"},
		{Username: "alice", CallerTokenID: "caller_a"},
	}
	want := "alice:caller_a\nalice:caller_z\nderek:caller_a\nderek:caller_b\n"
	if got := string(Canonical(grants)); got != want {
		t.Errorf("Canonical =\n%q\nwant\n%q", got, want)
	}
}

// TestCanonical_OrderIndependent proves the canonical form (and thus the hash)
// depends only on the SET of grants, not their input order.
func TestCanonical_OrderIndependent(t *testing.T) {
	a := []Grant{
		{Username: "u2", CallerTokenID: "c1"},
		{Username: "u1", CallerTokenID: "c2"},
		{Username: "u1", CallerTokenID: "c1"},
	}
	b := []Grant{
		{Username: "u1", CallerTokenID: "c1"},
		{Username: "u2", CallerTokenID: "c1"},
		{Username: "u1", CallerTokenID: "c2"},
	}
	if string(Canonical(a)) != string(Canonical(b)) {
		t.Errorf("Canonical not order-independent:\n%q\nvs\n%q", Canonical(a), Canonical(b))
	}
	if Hash(a) != Hash(b) {
		t.Errorf("Hash not order-independent: %q vs %q", Hash(a), Hash(b))
	}
	// Canonical must not mutate its input slice ordering.
	if a[0].Username != "u2" {
		t.Errorf("Canonical mutated caller input order: a[0]=%+v", a[0])
	}
}

// TestCanonical_MultipleCallersPerUsername covers the grouped case: one username
// with several callers expands to one sorted line per caller.
func TestCanonical_MultipleCallersPerUsername(t *testing.T) {
	grants := []Grant{
		{Username: "svc", CallerTokenID: "caller_3"},
		{Username: "svc", CallerTokenID: "caller_1"},
		{Username: "svc", CallerTokenID: "caller_2"},
	}
	want := "svc:caller_1\nsvc:caller_2\nsvc:caller_3\n"
	if got := string(Canonical(grants)); got != want {
		t.Errorf("Canonical = %q, want %q", got, want)
	}
}

// TestHash_EmptyIsEmptyString pins the historical empty-ACL behavior: no grants
// → "" (not the hash of empty bytes), so an Agent with no grants reports "".
func TestHash_EmptyIsEmptyString(t *testing.T) {
	if got := Hash(nil); got != "" {
		t.Errorf("Hash(nil) = %q, want empty string", got)
	}
	if got := Hash([]Grant{}); got != "" {
		t.Errorf("Hash(empty) = %q, want empty string", got)
	}
	if got := Canonical(nil); got != nil {
		t.Errorf("Canonical(nil) = %q, want nil", got)
	}
}

// TestHash_Wiring cross-checks that Hash is exactly "blake3:<hex>" over the
// canonical bytes — verifying the composition without re-implementing the
// canonical format (Canonical stays the single format owner).
func TestHash_Wiring(t *testing.T) {
	grants := []Grant{
		{Username: "u1", CallerTokenID: "c1"},
		{Username: "u1", CallerTokenID: "c2"},
	}
	sum := blake3.Sum256(Canonical(grants))
	want := "blake3:" + hex.EncodeToString(sum[:])
	if got := Hash(grants); got != want {
		t.Errorf("Hash = %q, want %q", got, want)
	}
}
