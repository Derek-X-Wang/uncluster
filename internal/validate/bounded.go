package validate

import (
	"fmt"
	"os"
	"path/filepath"
)

// BoundedFixtureOpts configures the bounded-class fixture check.
type BoundedFixtureOpts struct {
	// ScopeRoot is the throwaway parent dir the fixture works under. Defaults
	// to a fresh dir under os.TempDir(). The fixture creates a working subdir
	// inside it and removes that subdir entirely when done.
	ScopeRoot string
	// InjectFailure forces the fixture's work to fail partway, exercising the
	// snapshot/restore + self-clean path on the failure branch.
	InjectFailure bool
}

// RunBoundedFixture is the `bounded`-class fixture check (#108): it writes ONLY
// to a throwaway temp scope and self-cleans, leaving zero residue after success
// OR failure. It demonstrates — and tests — the mutating-guardrail machinery
// (preflight Snapshot, mid-run Restore on failure, self-clean) on a harmless
// target, without needing a real `sudo agent install`.
//
// Pattern every real bounded/privileged check should follow:
//  1. create a working scope,
//  2. Snapshot the paths about to be touched,
//  3. do the work; on error, Restore the snapshot,
//  4. ALWAYS remove the working scope (defer) so nothing leaks.
func RunBoundedFixture(opts BoundedFixtureOpts) CheckResult {
	scopeRoot := opts.ScopeRoot
	if scopeRoot == "" {
		scopeRoot = filepath.Join(os.TempDir(), "uncluster-validate-bounded")
		_ = os.MkdirAll(scopeRoot, 0o700)
	}

	work, err := os.MkdirTemp(scopeRoot, "bounded-*")
	if err != nil {
		return CheckResult{Name: "bounded-fixture", State: "fail",
			Raw: "create bounded scope: " + err.Error()}
	}
	// ALWAYS remove the working scope — this is the "self-clean" guarantee on
	// both the success and failure paths.
	defer os.RemoveAll(work)

	target := filepath.Join(work, "fixture.txt")
	// Snapshot before touching anything (target is absent → restore removes it).
	snap, err := Snapshot([]string{target})
	if err != nil {
		return CheckResult{Name: "bounded-fixture", State: "fail",
			Raw: "snapshot bounded scope: " + err.Error()}
	}

	doWork := func() error {
		if err := os.WriteFile(target, []byte("bounded fixture wrote here\n"), 0o600); err != nil {
			return fmt.Errorf("write fixture file: %w", err)
		}
		if opts.InjectFailure {
			return fmt.Errorf("injected bounded-fixture failure")
		}
		// Verify what we wrote (a real bounded check would assert something).
		b, err := os.ReadFile(target)
		if err != nil {
			return fmt.Errorf("read back fixture file: %w", err)
		}
		if len(b) == 0 {
			return fmt.Errorf("fixture file unexpectedly empty")
		}
		return nil
	}

	if runErr := doWork(); runErr != nil {
		// Restore the snapshot (undo the partial mutation) before the defer
		// removes the whole scope — exercising the restore path even though the
		// scope removal would also clean up here.
		_ = snap.Restore()
		return CheckResult{Name: "bounded-fixture", State: "fail",
			Raw: "bounded fixture failed (scope restored + removed): " + runErr.Error()}
	}

	return CheckResult{Name: "bounded-fixture", State: "ok",
		Raw: "bounded fixture wrote + verified + self-cleaned in a throwaway scope"}
}
