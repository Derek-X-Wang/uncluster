//go:build darwin

package gatekeeper

import "testing"

// TestParseUsedIDsDarwin covers the parser that turns `dscl . -list <path>
// <key>` output into the set of in-use UIDs/GIDs.
//
// This is the fix for the latent probe bug uncovered by #96's first t2-mac
// run: `dscl . -search /Users UniqueID <n>` exits 0 whether or not <n>
// matches, so the prior per-ID `-search` predicate reported EVERY id as "in
// use" and findFreeIDDarwin never found a free value ("no free system ID found
// in 200-499"). The reliable signal is list-membership, which is what this
// parser builds.
func TestParseUsedIDsDarwin(t *testing.T) {
	// Representative `dscl . -list /Users UniqueID` output: name then numeric
	// id, whitespace-separated, with the column gap macOS emits.
	const sample = `_amavisd                 83
_analyticsd              263
_accessoryupdater        278
root                     0
daemon                   1
nobody                   -2
`
	used := parseUsedIDsDarwin(sample)

	for _, want := range []int{83, 263, 278, 0, 1, -2} {
		if !used[want] {
			t.Errorf("expected %d to be parsed as in-use, but it was absent", want)
		}
	}
	if used[499] {
		t.Errorf("499 is not in the sample; must NOT be reported in-use")
	}
	if used[200] {
		t.Errorf("200 is not in the sample; must NOT be reported in-use")
	}
	if got := len(used); got != 6 {
		t.Errorf("parsed %d distinct ids, want 6", got)
	}
}

// TestParseUsedIDsDarwin_Garbage confirms the parser ignores malformed lines
// (blank lines, missing id column, non-numeric id) rather than panicking — a
// dscl quirk or a localized header should not corrupt the used-set.
func TestParseUsedIDsDarwin_Garbage(t *testing.T) {
	const sample = `
weirdrow
_svc                     not_a_number
_real                    321

`
	used := parseUsedIDsDarwin(sample)
	if !used[321] {
		t.Error("the one well-formed row (321) must be parsed")
	}
	if len(used) != 1 {
		t.Errorf("garbage rows must be skipped; got %d ids, want 1", len(used))
	}
}

// TestFindFreeIDDarwin_WithUsedSet ties the parser to the scanner: a free ID
// must be one that is NOT in the parsed used-set, allocated independently for
// UID vs GID. Models the empirical t2-mac condition (214 free UIDs, 213 free
// GIDs, none overlapping) at small scale: 499 used for UIDs but free for GIDs.
func TestFindFreeIDDarwin_WithUsedSet(t *testing.T) {
	usedUID := map[int]bool{499: true} // 499 taken as a UID
	usedGID := map[int]bool{498: true} // 498 taken as a GID

	uid, err := findFreeIDDarwin(func(id int) bool { return usedUID[id] })
	if err != nil {
		t.Fatalf("uid scan: %v", err)
	}
	if uid != 498 { // high-first, 499 skipped (used), 498 free
		t.Errorf("free UID = %d, want 498", uid)
	}

	gid, err := findFreeIDDarwin(func(id int) bool { return usedGID[id] })
	if err != nil {
		t.Fatalf("gid scan: %v", err)
	}
	if gid != 499 { // high-first, 499 free for GIDs
		t.Errorf("free GID = %d, want 499", gid)
	}
}
