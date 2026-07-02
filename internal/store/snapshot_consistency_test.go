package store_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/derek-x-wang/uncluster/internal/policyhash"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// TestGetPolicySnapshot_HashMatchesPrincipals proves the fix for #41: a
// snapshot's (version, hash) and Principals come from the same point-in-time
// view of the ACL. Without the fix the version/hash and principals were read
// in two separate non-tx queries; a concurrent CreateACL/DeleteACL between
// them returned a snapshot whose claimed hash didn't match the principals it
// carried — the Agent would then report applied_hash != desired_hash forever.
//
// Test mechanism: one goroutine churns ACL rows (Create+Delete cycles); a
// reader goroutine pulls GetPolicySnapshot many times and recomputes the hash
// over the returned principals using the same canonical serialisation the
// store uses internally. If they ever disagree, the snapshot was torn.
func TestGetPolicySnapshot_HashMatchesPrincipals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}
	s := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ag, err := s.CreateAgent(ctx, store.NewAgentParams{Name: "snap-cons"})
	if err != nil {
		t.Fatal(err)
	}
	// Pre-mint a pool of caller tokens to churn through.
	const tokenCount = 8
	tokens := make([]string, tokenCount)
	for i := range tokens {
		tk, err := s.CreateToken(ctx, store.NewTokenParams{
			Kind:       store.TokenCaller,
			SecretHash: fmt.Sprintf("h%d", i),
			Label:      fmt.Sprintf("caller-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = tk.ID
	}

	var writerErr, readerErr atomic.Value
	var reads atomic.Int64
	var mismatches atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer goroutine: rapid CreateACL + DeleteACL cycles.
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			tokenID := tokens[i%tokenCount]
			username := fmt.Sprintf("u%d", i%3)
			entry, err := s.CreateACL(ctx, store.CreateACLParams{
				CallerTokenID: tokenID, AgentID: ag.ID, Username: username,
			})
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				writerErr.Store(err)
				return
			}
			// Immediately delete — the snapshot reader is racing this delete
			// against the matching create elsewhere in the loop.
			if err := s.DeleteACL(ctx, entry.ID); err != nil {
				if ctx.Err() != nil {
					return
				}
				writerErr.Store(err)
				return
			}
			i++
		}
	}()

	// Reader goroutine: GetPolicySnapshot in a tight loop, recompute the hash
	// over the returned Principals, compare to the snapshot's claimed hash.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			snap, err := s.GetPolicySnapshot(ctx, ag.ID)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				readerErr.Store(err)
				return
			}
			reads.Add(1)
			expectHash := canonicalPolicyHash(snap.Principals)
			if snap.Hash != expectHash {
				mismatches.Add(1)
				readerErr.Store(fmt.Errorf(
					"snapshot hash %q != recomputed hash %q over Principals %+v",
					snap.Hash, expectHash, snap.Principals))
				return
			}
		}
	}()

	time.Sleep(1500 * time.Millisecond)
	close(stop)
	wg.Wait()

	if v := writerErr.Load(); v != nil {
		t.Fatalf("writer: %v", v)
	}
	if reads.Load() < 100 {
		t.Logf("warning: only %d reads completed; concurrency window may be too small", reads.Load())
	}
	if got := mismatches.Load(); got != 0 {
		t.Fatalf("%d torn snapshots out of %d reads. last error: %v",
			got, reads.Load(), readerErr.Load())
	}
}

// canonicalPolicyHash recomputes the policy hash from a snapshot's grouped
// Principals by flattening them back to (username, caller) grants and asking the
// canonical-form module — the SAME module the store hashes through — so this
// test no longer re-implements the serialization/hash. It only reshapes data;
// the format (sorted one-line-per-grant "username:caller\n" + blake3) lives
// solely in internal/policyhash.
func canonicalPolicyHash(principals []store.PolicyPrincipal) string {
	var grants []policyhash.Grant
	for _, p := range principals {
		for _, c := range p.CallerTokenIDs {
			grants = append(grants, policyhash.Grant{Username: p.Username, CallerTokenID: c})
		}
	}
	return policyhash.Hash(grants)
}
