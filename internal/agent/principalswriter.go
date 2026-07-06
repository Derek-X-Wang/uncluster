package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// This file holds the cross-platform contract between the low-priv
// UnclusterAgent service and the LocalSystem UnclusterPrincipalsWriter service
// (#127, ADR-0004 Windows amendment). The wire shapes and (de)serialisation are
// platform-neutral so they are unit-testable on the CI Linux host; the actual
// spool I/O, SCM handshake, and ACL syscalls live in the windows-tagged files.
//
// The split exists because Win32-OpenSSH silently ignores an
// AuthorizedPrincipalsFile that carries a write-class ACE for any principal
// outside {SYSTEM, Administrators, connecting-user, TrustedInstaller}. The
// low-priv agent therefore cannot itself write the live file; it submits a
// desired-state to a spool and the LocalSystem writer renders SYSTEM-owned
// files with a PROTECTED {SYSTEM, Administrators} DACL.

// spoolPolicyFile is the desired-state file the agent writes (atomically,
// tmp→rename) into the spool dir. The writer treats it as UNTRUSTED input.
const spoolPolicyFile = "policy.json"

// spoolAppliedFile is the applied-status file the writer writes (atomically)
// after each apply attempt. The agent polls it to resolve apply success.
const spoolAppliedFile = "applied.json"

// desiredState is the policy snapshot the agent hands to the writer. It
// deliberately carries ONLY the data the writer needs to render files. It does
// NOT carry any path, owner, or DACL hint — all of those are hardcoded in the
// writer so a compromised agent cannot redirect a write or weaken an ACL. The
// writer re-validates every Username and CallerTokenID before rendering.
type desiredState struct {
	Version    int64                 `json:"version"`
	Hash       string                `json:"hash"`
	Principals []api.PolicyPrincipal `json:"principals"`

	// Deprovision, when true, tells the LocalSystem writer that this apply is the
	// terminal deprovision wipe: after rendering the (empty) principals it must
	// remove its OWN service so it never outlives the agent (#127 invariant; #182
	// spool-mediated self-removal). It is a pure boolean flag — the writer takes
	// NO path or argument from the payload; it only ever deletes its own,
	// compiled-in-named service. omitempty keeps every non-deprovision apply's
	// spool bytes (and thus its digest) byte-identical to before.
	Deprovision bool `json:"deprovision,omitempty"`
}

// deprovisionDesiredState is the terminal wipe the agent submits to the spool on
// deprovision (410 Gone): an empty render (version 0, no principals) carrying the
// Deprovision flag so the writer both wipes AND self-removes. Version 0 matches
// the historical empty-wipe shape; the Deprovision field gives it a distinct
// spool digest so the writer always acts on it even right after a version-0
// fail-closed wipe.
func deprovisionDesiredState() desiredState {
	return desiredState{Deprovision: true}
}

// desiredStateRequestsDeprovision reports whether the spool bytes carry a valid
// deprovision signal. It is the writer's recognition of the terminal signal
// across the untrusted privilege boundary: malformed bytes are NOT a deprovision
// (false), so a garbage spool file can never trigger a self-delete.
func desiredStateRequestsDeprovision(b []byte) bool {
	d, err := unmarshalDesiredState(b)
	if err != nil {
		return false
	}
	return d.Deprovision
}

// shouldSelfRemoveOnApply decides whether the writer should remove its own
// service after an apply: only when the applied desired-state requested
// deprovision AND the (wipe) apply succeeded. A failed apply must NOT self-remove
// — the wipe is unconfirmed, so the writer stays up to retry. Platform-neutral so
// the whole decision is unit-tested off Windows; the Windows tick calls it and
// performs only the OS-specific service Delete().
func shouldSelfRemoveOnApply(b []byte, st appliedStatus) bool {
	return st.Status == "ok" && desiredStateRequestsDeprovision(b)
}

// appliedStatus is what the writer reports back after each apply attempt. The
// agent matches Version+Hash against the desired-state it submitted; Status is
// "ok" or "failed" and Error is populated on failure so a writer failure
// surfaces as a visible failed apply rather than a silent hang.
type appliedStatus struct {
	AppliedVersion int64  `json:"applied_version"`
	AppliedHash    string `json:"applied_hash"`
	Status         string `json:"status"` // "ok" | "failed"
	Error          string `json:"error,omitempty"`
}

// desiredStateFromPayload projects an api.PolicyPayload into the spool
// desired-state shape.
func desiredStateFromPayload(snap api.PolicyPayload) desiredState {
	return desiredState{
		Version:    snap.Version,
		Hash:       snap.Hash,
		Principals: snap.Principals,
	}
}

// toPayload reconstructs the api.PolicyPayload the writer renders from. The
// writer never trusts these fields blindly — renderPrincipalsDir re-validates
// every username and caller_token_id.
func (d desiredState) toPayload() api.PolicyPayload {
	return api.PolicyPayload{
		Version:    d.Version,
		Hash:       d.Hash,
		Principals: d.Principals,
	}
}

// marshalDesiredState serialises a desired-state for the spool.
func marshalDesiredState(d desiredState) ([]byte, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("marshal desired-state: %w", err)
	}
	return b, nil
}

// unmarshalDesiredState parses a spool desired-state. The writer calls this on
// untrusted bytes; a parse error is reported as a failed apply, never a panic.
func unmarshalDesiredState(b []byte) (desiredState, error) {
	var d desiredState
	if err := json.Unmarshal(b, &d); err != nil {
		return desiredState{}, fmt.Errorf("parse desired-state: %w", err)
	}
	return d, nil
}

// marshalAppliedStatus serialises an applied-status for the spool.
func marshalAppliedStatus(s appliedStatus) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal applied-status: %w", err)
	}
	return b, nil
}

// unmarshalAppliedStatus parses a spool applied-status.
func unmarshalAppliedStatus(b []byte) (appliedStatus, error) {
	var s appliedStatus
	if err := json.Unmarshal(b, &s); err != nil {
		return appliedStatus{}, fmt.Errorf("parse applied-status: %w", err)
	}
	return s, nil
}

// matchesDesired reports whether an applied-status corresponds to the
// desired-state the agent submitted: same version AND same hash. The agent uses
// this to ignore stale applied.json left from a previous round-trip while it
// polls for the writer to catch up to the version+hash it just submitted.
func (s appliedStatus) matchesDesired(d desiredState) bool {
	return s.AppliedVersion == d.Version && s.AppliedHash == d.Hash
}

// pollApplied waits for the writer's applied-status by calling read() every
// interval until one of three things happens:
//
//   - read() returns (status, true): the writer reported a status matching the
//     submitted desired-state → returns (status, true, nil). The caller inspects
//     status.Status ("ok" vs "failed").
//   - ctx is cancelled: the Agent is shutting down → returns (zero, false,
//     ctx.Err()) PROMPTLY, without blocking out the remaining deadline. This is
//     the #153 fix: on Windows the wait could otherwise stall Agent Run()
//     shutdown for the full applyTimeout when the LocalSystem PrincipalsWriter is
//     absent or slow, tripping the shutdown-race stress test's per-iteration
//     deadline.
//   - deadline elapses: returns (zero, false, nil) so the caller renders the
//     visible "writer did not apply within N" timeout error (#127: a writer
//     failure must surface as a failed apply, never a silent hang).
//
// The read closure is injected so this loop is platform-neutral and unit-testable
// on any host; the Windows apply path supplies a closure over
// readMatchingAppliedStatus(spoolAppliedPath(), d).
func pollApplied(ctx context.Context, deadline time.Time, interval time.Duration, read func() (appliedStatus, bool)) (appliedStatus, bool, error) {
	for {
		if st, ok := read(); ok {
			return st, true, nil
		}
		if !time.Now().Before(deadline) {
			return appliedStatus{}, false, nil
		}
		// Interruptible sleep: wake on the poll interval OR on shutdown. Waiting
		// via select (not time.Sleep) is what makes the wait cancellable.
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return appliedStatus{}, false, ctx.Err()
		case <-timer.C:
		}
	}
}

// desiredStateDigest is a short stable digest of the serialised desired-state.
// The writer uses it to decide whether a spool policy.json is NEW (different
// from the one it last applied) so it does not re-render on every poll for an
// unchanged desired-state. Version+Hash alone are insufficient because the
// server may legitimately re-send the same version after a writer failure; the
// digest over the full bytes is the robust change signal.
func desiredStateDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// applyDesiredStateBytes is the writer's core, platform-neutral apply: it parses
// the (untrusted) spool bytes, re-validates strictly, and renders the per-user
// files into principalsDir, returning the applied-status to report. It is shared
// between the Windows writer service and tests so the security-critical
// re-validation + render path is exercised on the CI Linux host (where
// restrictPrincipalsFileACL is a no-op) as well as on Windows.
//
// principalsDir is supplied by the caller (the Windows writer hardcodes
// WindowsPrincipalsDir; tests pass a temp dir). It is NEVER taken from the spool
// bytes — a compromised agent cannot redirect the writer's target.
//
// Failure modes — malformed bytes, a traversal username, a glob/newline-bearing
// caller_token_id, or a render error — all return a "failed" status with the
// error, never a panic and never a partial silent success.
func applyDesiredStateBytes(principalsDir string, b []byte) appliedStatus {
	d, err := unmarshalDesiredState(b)
	if err != nil {
		// Cannot key on version+hash (unknown); report a generic failure. The
		// agent's poll will not match it and will time out → visible failure.
		return appliedStatus{Status: "failed", Error: err.Error()}
	}
	snap := d.toPayload()
	if err := validatePolicyPayload(snap); err != nil {
		return appliedStatus{
			AppliedVersion: d.Version, AppliedHash: d.Hash,
			Status: "failed", Error: err.Error(),
		}
	}
	if err := renderPrincipalsDir(principalsDir, snap); err != nil {
		return appliedStatus{
			AppliedVersion: d.Version, AppliedHash: d.Hash,
			Status: "failed", Error: err.Error(),
		}
	}
	return appliedStatus{AppliedVersion: d.Version, AppliedHash: d.Hash, Status: "ok"}
}
