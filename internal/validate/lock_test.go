package validate

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestValidationLock_MutualExclusion is the load-bearing concurrency test
// (#108, ADR-0009): the validation lock prevents two agents mutating the same
// real machine concurrently. Two acquirers contend; exactly one proceeds, the
// other is refused. Run under -race to catch a data race in the primitive.
func TestValidationLock_MutualExclusion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "validation.lock")

	first, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("first AcquireLock failed: %v", err)
	}
	// A second acquire while the first is held must be refused.
	if _, err := AcquireLock(path); err == nil {
		t.Fatal("second AcquireLock succeeded while lock held — mutual exclusion broken")
	}
	// After release, a fresh acquire succeeds.
	if err := first.Release(); err != nil {
		t.Fatalf("Release failed: %v", err)
	}
	second, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("AcquireLock after release failed: %v", err)
	}
	_ = second.Release()
}

// TestValidationLock_ConcurrentRace spins many goroutines all racing to acquire
// the SAME lock; exactly one may hold it at a time. Each winner increments a
// shared counter while holding the lock and asserts it never sees concurrent
// entry. Under -race this also flags any unsynchronized access.
func TestValidationLock_ConcurrentRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "validation.lock")

	const goroutines = 20
	var (
		mu        sync.Mutex
		inside    int // how many are inside the critical section right now
		successes int
		maxInside int
	)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lk, err := AcquireLock(path)
			if err != nil {
				return // refused — expected for all but the holder at any instant
			}
			mu.Lock()
			inside++
			successes++
			if inside > maxInside {
				maxInside = inside
			}
			mu.Unlock()

			time.Sleep(time.Millisecond) // hold briefly to widen the contention window

			mu.Lock()
			inside--
			mu.Unlock()
			_ = lk.Release()
		}()
	}
	wg.Wait()

	if maxInside > 1 {
		t.Errorf("max concurrent lock holders = %d, want 1 (mutual exclusion violated)", maxInside)
	}
	if successes == 0 {
		t.Error("no goroutine ever acquired the lock")
	}
}

// TestValidationLock_BreaksStaleLock verifies a lock left by a dead process
// (old timestamp) can be broken so a crashed mutating run does not wedge
// validation forever.
func TestValidationLock_BreaksStaleLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "validation.lock")

	// Write a stale lock by hand (old timestamp, bogus pid).
	if err := writeStaleLockForTest(path, 999999, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	lk, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("AcquireLock should break a stale lock, got: %v", err)
	}
	_ = lk.Release()
}
