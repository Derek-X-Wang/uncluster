package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPrincipalsFileContent covers the security-critical core of
// `uncluster agent principals %u` (#185). sshd runs it with an attacker-
// influenceable %u, so it must return a user's principals for a safe name and
// NOTHING (nil = deny) for anything that could escape the principals dir.
func TestPrincipalsFileContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ciuser"), []byte("caller_x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file that a traversal MUST NOT be able to reach.
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("TOPSECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("reads a valid user's principals", func(t *testing.T) {
		got := principalsFileContent(dir, "ciuser")
		if string(got) != "caller_x\n" {
			t.Fatalf("got %q, want %q", got, "caller_x\n")
		}
	})

	t.Run("missing user → nil (no principals)", func(t *testing.T) {
		if got := principalsFileContent(dir, "nobody"); got != nil {
			t.Fatalf("expected nil for a user with no file, got %q", got)
		}
	})

	// Traversal / unsafe inputs must all deny (nil), never read outside dir.
	for _, bad := range []string{
		"../secret", "../../etc/passwd", "a/b", "/etc/passwd", ".", "..", "",
		filepath.Join("..", filepath.Base(secret)),
	} {
		t.Run("denies unsafe input "+bad, func(t *testing.T) {
			if got := principalsFileContent(dir, bad); got != nil {
				t.Fatalf("unsafe username %q returned %q; must deny (nil)", bad, got)
			}
		})
	}

	t.Run("empty dir → nil", func(t *testing.T) {
		if got := principalsFileContent("", "ciuser"); got != nil {
			t.Fatalf("empty dir must deny, got %q", got)
		}
	})
}
