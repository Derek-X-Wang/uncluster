package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/derek-x-wang/uncluster/internal/api"
)

// policyState tracks the last-applied policy result for inclusion in
// subsequent heartbeats. All fields are guarded by Agent.policyMu.
type policyState struct {
	appliedVersion  int64
	appliedHash     string
	lastApplyStatus string  // "ok" | "failed"
	lastApplyError  *string // non-nil on failure
	lastApplyAt     int64   // unix seconds
}

// applyWorker serialises policy apply requests via a channel. applyPolicy
// sends to this channel; the goroutine consumes one at a time. The channel
// is buffered by 1 so that a second request arriving while one is in-flight
// replaces the pending-but-not-yet-started request (coalesce semantics).
type applyRequest struct {
	snapshot api.PolicyPayload
}

// runApplyPolicy performs the atomic principals-dir rewrite for a given policy
// snapshot. It updates a.policyState on completion.
func (a *Agent) runApplyPolicy(snap api.PolicyPayload) {
	now := time.Now().Unix()
	dir := a.cfg.ExpectedPaths.PrincipalsDir
	if dir == "" {
		a.logger.Warn("policy apply: principals_dir not configured; skipping")
		return
	}

	if err := a.doApplyPolicy(dir, snap); err != nil {
		errStr := err.Error()
		a.logger.Warn("policy apply failed", "version", snap.Version, "err", err)
		a.policyMu.Lock()
		a.policyStateVal.lastApplyStatus = "failed"
		a.policyStateVal.lastApplyError = &errStr
		a.policyStateVal.lastApplyAt = now
		// Do NOT advance appliedVersion on failure.
		a.policyMu.Unlock()
		return
	}

	a.logger.Info("policy applied", "version", snap.Version, "hash", snap.Hash,
		"principals", len(snap.Principals))
	a.policyMu.Lock()
	a.policyStateVal.appliedVersion = snap.Version
	a.policyStateVal.appliedHash = snap.Hash
	a.policyStateVal.lastApplyStatus = "ok"
	a.policyStateVal.lastApplyError = nil
	a.policyStateVal.lastApplyAt = now
	a.policyMu.Unlock()
}

// doApplyPolicy is the per-platform apply dispatcher. On Unix it rewrites the
// principals dir in-process (the low-priv service account holds the dir grant
// and sshd accepts a root/service-owned file). On Windows it hands the
// validated desired-state to the LocalSystem UnclusterPrincipalsWriter via the
// spool, because Win32-OpenSSH rejects any AuthorizedPrincipalsFile carrying a
// write-class ACE for the low-priv agent account (#127, ADR-0004 Windows
// amendment). The implementations live in policy_apply_unix.go and
// policy_apply_windows.go so the non-Windows behaviour stays byte-identical.

// renderPrincipalsDir performs the atomic principals-dir rewrite for snap into
// dir: it validates every username and caller_token_id, writes one file per
// user (tmp→rename, applying restrictPrincipalsFileACL on the tmp file before
// the rename so the live file never appears with a wrong ACL), deletes files
// for users dropped from the policy, and deletes the file for any user whose
// caller set is empty.
//
// This is the SINGLE renderer shared by the Unix in-process apply path and the
// Windows LocalSystem writer, so the on-disk shape can never diverge between
// platforms. On Unix restrictPrincipalsFileACL is a no-op; on Windows it sets
// owner=SYSTEM + a PROTECTED {SYSTEM, Administrators} DACL (#127).
func renderPrincipalsDir(dir string, snap api.PolicyPayload) error {
	// Ensure principals dir exists.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("principals dir: %w", err)
	}

	if err := validatePolicyPayload(snap); err != nil {
		return err
	}

	// Build set of usernames in the new policy.
	wantUsers := map[string]struct{}{}
	for _, p := range snap.Principals {
		wantUsers[p.Username] = struct{}{}
	}

	// Write per-user principals files.
	for _, p := range snap.Principals {
		if len(p.CallerTokenIDs) == 0 {
			// No callers → delete file (treated like removal).
			target := filepath.Join(dir, p.Username)
			if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove empty principals for %q: %w", p.Username, err)
			}
			delete(wantUsers, p.Username)
			continue
		}
		if err := atomicWritePrincipals(dir, p.Username, p.CallerTokenIDs); err != nil {
			return fmt.Errorf("write principals for %q: %w", p.Username, err)
		}
	}

	// Delete files for users no longer in policy.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read principals dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if _, keep := wantUsers[name]; !keep {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove stale principals %q: %w", name, err)
			}
		}
	}
	return nil
}

// validatePolicyPayload validates every username and caller_token_id in snap
// before any file is touched. Reused by both the renderer and (defensively) by
// the Windows writer when it re-validates a spool-delivered desired-state — the
// agent is treated as untrusted across the privilege boundary (#127).
func validatePolicyPayload(snap api.PolicyPayload) error {
	for _, p := range snap.Principals {
		if err := validateUsername(p.Username); err != nil {
			return fmt.Errorf("invalid username %q: %w", p.Username, err)
		}
		for _, c := range p.CallerTokenIDs {
			if err := validateCallerTokenID(c); err != nil {
				return fmt.Errorf("invalid caller_token_id %q: %w", c, err)
			}
		}
	}
	return nil
}

// atomicWritePrincipals writes lines to <dir>/<username> atomically via
// tmp→rename. The per-file ACL is applied to the tmp file BEFORE the rename:
// a same-volume rename preserves the security descriptor, so the live file is
// never visible to sshd with an inherited (agent-writable) ACL. On Unix
// restrictPrincipalsFileACL is a no-op.
func atomicWritePrincipals(dir, username string, callerTokenIDs []string) error {
	tmp := filepath.Join(dir, username+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	for _, c := range callerTokenIDs {
		if _, err := fmt.Fprintln(f, c); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("write: %w", err)
		}
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
	// Apply the per-file ACL on the tmp file before rename (no-op on Unix).
	if err := restrictPrincipalsFileACL(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("restrict principals file acl: %w", err)
	}
	target := filepath.Join(dir, username)
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// validateCallerTokenID rejects any caller_token_id that contains chars
// dangerous in an AuthorizedPrincipals context (newline, whitespace, comma, glob).
func validateCallerTokenID(s string) error {
	if s == "" {
		return fmt.Errorf("empty caller_token_id")
	}
	for _, r := range s {
		if unicode.IsSpace(r) || r == ',' || r == '*' || r == '?' || r == '[' || r == ']' {
			return fmt.Errorf("disallowed character %q", r)
		}
	}
	return nil
}

// validateUsername rejects obviously unsafe usernames.
func validateUsername(s string) error {
	if s == "" {
		return fmt.Errorf("empty username")
	}
	// Reject anything that would escape the directory or contain unsafe chars.
	if strings.ContainsAny(s, "/\\\x00\n\r\t ") || s == "." || s == ".." {
		return fmt.Errorf("unsafe username %q", s)
	}
	return nil
}

