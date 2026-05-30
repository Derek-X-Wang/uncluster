package validate

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBoundedFixture_SelfCleansOnSuccess verifies the bounded-class fixture
// (#108) writes only to a throwaway temp scope and leaves ZERO residue after a
// successful run — exercising the bounded safety class without a real install.
func TestBoundedFixture_SelfCleansOnSuccess(t *testing.T) {
	root := t.TempDir()
	res := RunBoundedFixture(BoundedFixtureOpts{ScopeRoot: root})

	if res.State != "ok" {
		t.Errorf("bounded fixture State = %q, want ok\nraw: %s", res.State, res.Raw)
	}
	assertScopeEmpty(t, root)
}

// TestBoundedFixture_SelfCleansOnFailure verifies that even when the fixture's
// work fails partway, the snapshot/restore + cleanup machinery leaves zero
// residue — the bounded contract holds on failure too.
func TestBoundedFixture_SelfCleansOnFailure(t *testing.T) {
	root := t.TempDir()
	res := RunBoundedFixture(BoundedFixtureOpts{ScopeRoot: root, InjectFailure: true})

	if res.State != "fail" {
		t.Errorf("bounded fixture with injected failure State = %q, want fail", res.State)
	}
	assertScopeEmpty(t, root)
}

// assertScopeEmpty asserts the scope root contains no leftover fixture files.
func assertScopeEmpty(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read scope root: %v", err)
	}
	for _, e := range entries {
		// The fixture must remove its own working dir entirely.
		t.Errorf("bounded fixture left residue in scope: %s", filepath.Join(root, e.Name()))
	}
}
