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

// doApplyPolicy writes/removes all principals files for snap atomically.
func (a *Agent) doApplyPolicy(dir string, snap api.PolicyPayload) error {
	// Ensure principals dir exists.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("principals dir: %w", err)
	}

	// Validate all caller_token_ids before writing anything.
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

// atomicWritePrincipals writes lines to <dir>/<username> atomically via tmp→rename.
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

