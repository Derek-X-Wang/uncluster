//go:build windows

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// wipePrincipals on Windows submits an EMPTY desired-state to the LocalSystem
// writer (version 0, no principals), which renders an empty dir — deleting every
// per-user file. The agent itself holds NO delete permission on the SYSTEM-owned
// principals files (#127), so the wipe MUST go through the writer. Best-effort:
// a writer failure/timeout is logged by doApplyPolicy and ignored here, because
// deprovision (marker + exit) must proceed regardless; the supervisor will not
// restart the agent, and a stale principal expires at TTL anyway.
func (a *Agent) wipePrincipals(_ string) {
	if err := a.doApplyPolicy("", api.PolicyPayload{Version: 0, Hash: "", Principals: nil}); err != nil {
		a.logger.Warn("deprovision: writer wipe failed; principals may persist until TTL/next apply", "err", err)
	}
}

// applyTimeout bounds how long the agent waits for the LocalSystem
// UnclusterPrincipalsWriter to report an applied-status matching the
// desired-state the agent just submitted. If the writer is stopped, crashed, or
// wedged, the agent must surface a VISIBLE failed apply (so appliedVersion does
// NOT advance and the Control plane keeps re-sending policy) rather than hang
// forever (#127 acceptance: "a writer failure surfaces as a visible failed
// apply, not a silent hang").
const applyTimeout = 30 * time.Second

// applyPollInterval is how often the agent re-reads applied.json while waiting.
const applyPollInterval = 250 * time.Millisecond

// doApplyPolicy on Windows does NOT write the principals files itself. The
// low-priv `NT SERVICE\UnclusterAgent` account cannot hold a write-class ACE on
// any AuthorizedPrincipalsFile (Win32-OpenSSH would then silently ignore the
// file — #127), and it deliberately lacks SeRestore to fix the owner. Instead
// it hands the validated desired-state to the LocalSystem
// UnclusterPrincipalsWriter via a spool file and polls for the writer's
// applied-status.
//
// Flow:
//  1. Validate the payload locally (fail fast on a bad policy without bothering
//     the writer — the writer re-validates regardless, this is defense in
//     depth on both sides of the boundary).
//  2. Atomically (tmp→rename) write policy.json into the spool.
//  3. Poll applied.json until an applied-status matching this version+hash
//     appears, or applyTimeout elapses.
//  4. Return nil on a matching "ok"; return an error on a matching "failed" or
//     on timeout. The caller (runApplyPolicy) maps a nil return to advancing
//     appliedVersion and an error to a failed apply that does not advance it.
//
// The `dir` argument is accepted for signature parity with the Unix path but is
// intentionally NOT forwarded to the writer: the writer's target dir is
// hardcoded (WindowsPrincipalsDir) so a compromised agent cannot redirect it.
func (a *Agent) doApplyPolicy(_ string, snap api.PolicyPayload) error {
	// Local validation: reject obviously bad policy before it reaches the spool.
	if err := validatePolicyPayload(snap); err != nil {
		return err
	}

	if err := ensureSpoolDir(); err != nil {
		return fmt.Errorf("spool dir: %w", err)
	}

	d := desiredStateFromPayload(snap)
	b, err := marshalDesiredState(d)
	if err != nil {
		return err
	}
	if err := atomicWriteSpoolFile(spoolPolicyPath(), b); err != nil {
		return fmt.Errorf("write spool desired-state: %w", err)
	}

	// Poll for the writer's applied-status matching this version+hash.
	deadline := time.Now().Add(applyTimeout)
	for {
		st, ok := readMatchingAppliedStatus(spoolAppliedPath(), d)
		if ok {
			if st.Status == "ok" {
				return nil
			}
			// Writer reported a failure for THIS desired-state.
			if st.Error != "" {
				return fmt.Errorf("principals writer failed: %s", st.Error)
			}
			return fmt.Errorf("principals writer reported failed apply (version %d)", st.AppliedVersion)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("principals writer did not apply version %d within %s (is the UnclusterPrincipalsWriter service running?)",
				snap.Version, applyTimeout)
		}
		time.Sleep(applyPollInterval)
	}
}

// readMatchingAppliedStatus reads applied.json and returns (status, true) only
// if it parses AND matches the submitted desired-state's version+hash.
// A missing file, parse error, or stale (non-matching) status returns
// (zero, false) so the caller keeps polling. This guarantees a stale applied.json
// from a prior round-trip never falsely resolves the current apply.
func readMatchingAppliedStatus(path string, d desiredState) (appliedStatus, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return appliedStatus{}, false
	}
	st, err := unmarshalAppliedStatus(b)
	if err != nil {
		return appliedStatus{}, false
	}
	if !st.matchesDesired(d) {
		return appliedStatus{}, false
	}
	return st, true
}

// atomicWriteSpoolFile writes b to path via tmp→rename + fsync, so the writer
// (or agent, for applied.json) never observes a half-written spool file. The
// tmp file is created in the same directory so the rename stays on one volume.
func atomicWriteSpoolFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	_ = dir // documented: tmp is in the same dir to keep the rename same-volume
	return nil
}
