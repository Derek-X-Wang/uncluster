// Package agent — update-host allowlist
//
// Implements the install-time-pinned hostname allowlist for binary self-
// update downloads (issue #39, ADR-0006). The Control plane decides
// *when* to update; this code enforces that the downloaded *what* is
// hosted on a trusted name even if the Control plane is compromised.
//
// See `docs/adr/0006-self-update-channel.md` for the trust-model
// rationale and `CONTEXT.md` for the term distinctions (Agent,
// Control plane, Caller).

package agent

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// DefaultUpdateHostAllowlist is what the Agent uses when agent.toml does
// not pin update_host_allowlist explicitly. Matches the historical
// upstream release host for the project. Operators who want to host
// updates elsewhere can override at install time (see install command).
//
// Returning a *copy* is the caller's responsibility — we never mutate
// this slice in place, but defensive copies upstream avoid accidental
// shared-state aliasing across multiple Config consumers.
var DefaultUpdateHostAllowlist = []string{"github.com"}

// ErrDisallowedHost is returned by ValidateUpdateURL when the URL's
// hostname is not in the configured allowlist. Wrapped errors include the
// rejected hostname and the configured allowlist for log inspection.
var ErrDisallowedHost = errors.New("selfupdate: disallowed host")

// AllowedUpdateHosts returns the effective allowlist for this Config:
//
//   - If the operator did not set update_host_allowlist in agent.toml
//     (the field decodes as nil), returns DefaultUpdateHostAllowlist —
//     pre-existing installs keep working without re-enrollment.
//   - If the operator explicitly set it (including to []), returns the
//     configured value verbatim. Empty = updates disabled, every URL
//     rejected.
//
// This distinction matters for #39: an absent field is an unmodernised
// install; an explicit `update_host_allowlist = []` is the operator
// expressing "no updates allowed."
func (c Config) AllowedUpdateHosts() []string {
	if c.UpdateHostAllowlist == nil {
		// Return a copy so callers can't accidentally mutate the package
		// default. Defensive — no current caller does, but cheap.
		out := make([]string, len(DefaultUpdateHostAllowlist))
		copy(out, DefaultUpdateHostAllowlist)
		return out
	}
	return c.UpdateHostAllowlist
}

// ValidateUpdateURL parses rawURL and rejects it unless its hostname
// matches one of the entries in allowlist (case-insensitive, exact
// match — `github.com` allows ONLY `github.com`, NOT `evil.github.com`).
//
// Ports on the URL are ignored for the comparison; the allowlist
// entries are pure hostnames. So `github.com:443` validates against
// allowlist entry `github.com`.
//
// Empty allowlist always rejects (matches the "updates disabled"
// posture). Invalid URLs return a parse error that wraps
// ErrDisallowedHost so callers can branch on errors.Is once.
func ValidateUpdateURL(rawURL string, allowlist []string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: parse %q: %v", ErrDisallowedHost, rawURL, err)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: no host in %q", ErrDisallowedHost, rawURL)
	}
	for _, allowed := range allowlist {
		if strings.EqualFold(host, allowed) {
			return nil
		}
	}
	return fmt.Errorf("%w: host %q not in allowlist %v", ErrDisallowedHost, host, allowlist)
}
