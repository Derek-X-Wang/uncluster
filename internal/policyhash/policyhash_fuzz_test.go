package policyhash

import "testing"

// FuzzCanonicalHash fuzzes the Policy canonical form + hash (#171). This format
// backs ADR-0007's bidirectional version handshake, so Canonical/Hash must be
// panic-free on arbitrary grant content and must satisfy their load-bearing
// contracts regardless of that content:
//   - deterministic: Hash(g) == Hash(g);
//   - order-independent: Hash sorts, so input order can't change the hash — else
//     the Control plane's desired_hash and an Agent's applied_hash could diverge
//     purely from row ordering and churn Policy pushes forever.
func FuzzCanonicalHash(f *testing.F) {
	f.Add("alice", "caller1", "bob", "caller2")
	f.Add("", "", "", "")
	f.Add("alice", "caller1", "alice", "caller1") // duplicate grants
	f.Add("a:b", "c\nd", "x", "y")                // separator-bearing content
	f.Fuzz(func(t *testing.T, u1, c1, u2, c2 string) {
		g := []Grant{{Username: u1, CallerTokenID: c1}, {Username: u2, CallerTokenID: c2}}

		// Panic-free.
		_ = Canonical(g)
		h := Hash(g)

		// Deterministic.
		if Hash(g) != h {
			t.Fatalf("Hash not deterministic for %+v", g)
		}

		// Order-independent (Canonical sorts a copy).
		rev := []Grant{g[1], g[0]}
		if Hash(rev) != h {
			t.Fatalf("Hash order-dependent: %q (reversed) != %q for %+v", Hash(rev), h, g)
		}

		// Canonical must not mutate its input.
		if g[0].Username != u1 || g[0].CallerTokenID != c1 || g[1].Username != u2 || g[1].CallerTokenID != c2 {
			t.Fatal("Canonical mutated its input slice")
		}
	})
}
