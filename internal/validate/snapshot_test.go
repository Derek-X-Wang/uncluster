package validate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSnapshotRestore_RoundTrip is the load-bearing safety test for #108: a
// mutating check snapshots the state it will touch, and on failure Restore
// returns it to exactly the snapshot. Covers all three transitions a mutation
// can cause: modify an existing file, create a new file (must be removed on
// restore), and delete an existing file (must be recreated on restore).
func TestSnapshotRestore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.conf")
	willDelete := filepath.Join(dir, "to-delete.conf")
	willCreate := filepath.Join(dir, "to-create.conf")

	if err := os.WriteFile(existing, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(willDelete, []byte("delete-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// willCreate does not exist yet.

	snap, err := Snapshot([]string{existing, willDelete, willCreate})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Simulate a mutating check: modify existing, delete willDelete, create
	// willCreate.
	if err := os.WriteFile(existing, []byte("MUTATED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(willDelete); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(willCreate, []byte("NEW\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Restore must undo all three.
	if err := snap.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if b, _ := os.ReadFile(existing); string(b) != "original\n" {
		t.Errorf("existing not restored: got %q", b)
	}
	if b, err := os.ReadFile(willDelete); err != nil || string(b) != "delete-me\n" {
		t.Errorf("deleted file not recreated: got %q err=%v", b, err)
	}
	if _, err := os.Stat(willCreate); !os.IsNotExist(err) {
		t.Errorf("created file not removed on restore (err=%v)", err)
	}

	// Mode is restored on Unix (Windows uses ACLs).
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(willDelete); err == nil {
			if perm := fi.Mode().Perm(); perm != 0o600 {
				t.Errorf("restored file mode = %#o, want 0600", perm)
			}
		}
	}
}

// TestSnapshotRestore_InjectedFailureLeavesClean models a mutating run that
// fails partway: it mutates several files, then an injected error triggers
// Restore. The machine must be left byte-identical to before the run.
func TestSnapshotRestore_InjectedFailureLeavesClean(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "ca.pub"),
		filepath.Join(dir, "drop-in.conf"),
		filepath.Join(dir, "agent.toml"),
	}
	want := map[string]string{}
	for i, p := range paths {
		content := "orig-" + string(rune('A'+i)) + "\n"
		want[p] = content
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	snap, err := Snapshot(paths)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Run a fake mutating step that fails after partially mutating.
	runErr := func() error {
		_ = os.WriteFile(paths[0], []byte("garbage\n"), 0o644)
		_ = os.Remove(paths[1])
		return os.ErrInvalid // injected mid-run failure
	}()
	if runErr != nil {
		if err := snap.Restore(); err != nil {
			t.Fatalf("Restore after injected failure: %v", err)
		}
	}

	for p, content := range want {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("file %s missing after restore: %v", p, err)
			continue
		}
		if string(b) != content {
			t.Errorf("file %s = %q after restore, want %q (machine not left clean)", p, b, content)
		}
	}
}
