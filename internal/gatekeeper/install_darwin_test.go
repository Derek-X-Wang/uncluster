//go:build darwin

package gatekeeper

import "testing"

// TestFindFreeIDDarwin_IndependentAllocation is the core regression test for
// #96 Bug 1: the old findFreeSystemIDDarwin required the SAME number to be
// free as both a UID and a GID and returned (id, id). On a dense host where
// free UIDs and free GIDs exist but never share a number, that coupled scan
// fails when independent allocation would succeed.
//
// We exercise the pure scanner with injected "in use" predicates that model
// non-overlapping free namespaces, then assert each scan returns a value free
// in its OWN namespace — and crucially that the chosen UID and GID need not
// match.
func TestFindFreeIDDarwin_IndependentAllocation(t *testing.T) {
	// Model a host where the entire 200-499 window is packed for UIDs EXCEPT
	// 250, and packed for GIDs EXCEPT 300. No number is simultaneously free in
	// both namespaces, so the old coupled scan would have failed with
	// "no free system UID/GID found".
	uidInUse := func(id int) bool { return id != 250 }
	gidInUse := func(id int) bool { return id != 300 }

	uid, err := findFreeIDDarwin(uidInUse)
	if err != nil {
		t.Fatalf("findFreeIDDarwin(uid) returned error: %v", err)
	}
	if uid != 250 {
		t.Errorf("free UID = %d, want 250 (the only free UID)", uid)
	}

	gid, err := findFreeIDDarwin(gidInUse)
	if err != nil {
		t.Fatalf("findFreeIDDarwin(gid) returned error: %v", err)
	}
	if gid != 300 {
		t.Errorf("free GID = %d, want 300 (the only free GID)", gid)
	}

	if uid == gid {
		t.Fatalf("UID and GID must be allocated independently; got matching value %d "+
			"— the coupling bug (#96) is back", uid)
	}
}

// TestFindFreeIDDarwin_HighFirst confirms the scan iterates high-to-low so low
// IDs stay free for future Apple-reserved expansion (preserving the existing
// allocation posture from the pre-#96 coupled scanner).
func TestFindFreeIDDarwin_HighFirst(t *testing.T) {
	// Everything in 200-499 is free; high-first must return 499.
	allFree := func(int) bool { return false }
	id, err := findFreeIDDarwin(allFree)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 499 {
		t.Errorf("high-first scan returned %d, want 499", id)
	}
}

// TestFindFreeIDDarwin_Exhausted confirms a genuinely-packed namespace (no free
// value anywhere in 200-499) returns an error rather than a bogus ID. This is
// the "hosted runner has zero allocatable system-ID space" condition that the
// t2-mac preflight detects and converts to a documented advisory xfail.
func TestFindFreeIDDarwin_Exhausted(t *testing.T) {
	allUsed := func(int) bool { return true }
	if _, err := findFreeIDDarwin(allUsed); err == nil {
		t.Fatal("expected error when the whole 200-499 window is in use, got nil")
	}
}

// TestFindFreeIDDarwin_BoundaryRespected confirms the scan never returns a
// value outside the 200-499 operator system-account window even when out-of-
// range IDs are free. 0-199 is Apple-reserved; 500+ is the interactive-user
// range (the runner user is 501). Widening into either is a rejected approach
// per #96.
func TestFindFreeIDDarwin_BoundaryRespected(t *testing.T) {
	// Free only outside the window (199 and 500). Inside is fully packed.
	inUse := func(id int) bool { return id >= 200 && id <= 499 }
	if _, err := findFreeIDDarwin(inUse); err == nil {
		t.Fatal("expected error: only out-of-window IDs free, but scan must stay in 200-499")
	}
}
