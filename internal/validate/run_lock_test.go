package validate

import (
	"path/filepath"
	"testing"
)

// TestRun_MutatingTakesLock verifies that a mutating run (bounded or above)
// acquires the validation lock, and a second concurrent mutating run against
// the same lock is refused — no interleaved mutation (#108 acceptance). An
// inspect run takes no lock (read-only needs no mutual exclusion).
func TestRun_MutatingTakesLock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "validation.lock")

	mkRunner := func(safety SafetyClass) *Runner {
		r := newTestRunner(t, &Runner{
			Safety:      safety,
			AllowMutate: true, // satisfy the gate for privileged
			AllowReboot: true, // and disruptive
			Check:       fakeCheck("ok", "{}"),
		})
		r.LockPath = lockPath
		return r
	}

	t.Run("inspect takes no lock", func(t *testing.T) {
		// Pre-hold the lock; an inspect run should still proceed (no contention).
		held, err := AcquireLock(lockPath)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Release()

		r := mkRunner(SafetyInspect)
		if _, err := r.Run(); err != nil {
			t.Errorf("inspect run should not be blocked by a held lock: %v", err)
		}
	})

	t.Run("mutating run refused while lock held", func(t *testing.T) {
		held, err := AcquireLock(lockPath)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Release()

		r := mkRunner(SafetyBounded)
		if _, err := r.Run(); err == nil {
			t.Error("mutating run should be refused while the validation lock is held")
		}
	})

	t.Run("mutating run proceeds and releases lock", func(t *testing.T) {
		r := mkRunner(SafetyBounded)
		if _, err := r.Run(); err != nil {
			t.Fatalf("mutating run with free lock should proceed: %v", err)
		}
		// Lock must be released afterward — a fresh acquire succeeds.
		lk, err := AcquireLock(lockPath)
		if err != nil {
			t.Errorf("lock not released after mutating run: %v", err)
		}
		_ = lk.Release()
	})
}
