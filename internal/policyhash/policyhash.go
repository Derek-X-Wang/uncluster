// Package policyhash owns the canonical serialization and blake3 hash of a
// Policy — the load-bearing format behind ADR-0007's bidirectional version
// handshake (the Control plane's desired_hash vs the Agent's applied_hash).
//
// It is the SINGLE definition of that format. The store computes an Agent's
// desired policy hash from its ACL rows through here; tests assert against this
// module rather than re-deriving the bytes; and any future consumer that
// verifies a received Policy hashes through the same code, so the two sides can
// never disagree on the bytes.
//
// Byte stability matters: the hash gates whether the Control plane re-pushes a
// Policy to an Agent, so any change to the canonical bytes re-hashes every
// existing Agent's policy and forces spurious version churn. The format is
// therefore pinned by a golden test.
package policyhash

import (
	"fmt"
	"sort"

	"lukechampine.com/blake3"
)

// Grant is one (username, caller_token_id) authorization pair — the atomic unit
// of the canonical form. A store ACL row maps 1:1 to a Grant.
type Grant struct {
	Username      string
	CallerTokenID string
}

// Canonical returns the canonical serialization of the given grants: one
// "username:caller\n" line PER GRANT, sorted by (username, caller_token_id).
//
// It is one line per grant — NOT a grouped "username:caller1,caller2" line.
// (Older comments in the store and its tests claimed grouping; the code has
// always emitted per-grant lines, and that is the byte-exact truth the version
// handshake depends on.) Returns nil for no grants, so an empty ACL has no
// canonical bytes (and Hash returns "").
//
// Canonical does not mutate its input: it sorts a copy.
func Canonical(grants []Grant) []byte {
	if len(grants) == 0 {
		return nil
	}
	sorted := make([]Grant, len(grants))
	copy(sorted, grants)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Username != sorted[j].Username {
			return sorted[i].Username < sorted[j].Username
		}
		return sorted[i].CallerTokenID < sorted[j].CallerTokenID
	})
	var b []byte
	for _, g := range sorted {
		b = append(b, g.Username...)
		b = append(b, ':')
		b = append(b, g.CallerTokenID...)
		b = append(b, '\n')
	}
	return b
}

// Hash returns "blake3:<hex>" over Canonical(grants), or "" when there are no
// grants. The empty-string case (not the hash of empty bytes) matches the
// store's historical behavior so an Agent with no grants reports applied_hash
// "" and matches the Control plane's empty desired_hash.
func Hash(grants []Grant) string {
	c := Canonical(grants)
	if len(c) == 0 {
		return ""
	}
	sum := blake3.Sum256(c)
	return fmt.Sprintf("blake3:%x", sum)
}
