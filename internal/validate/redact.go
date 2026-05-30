package validate

import "regexp"

// tokenRe matches an Uncluster token of the form uct_<kind>_<id>_<secret>
// (see internal/token: kind ∈ join|agent|cli|caller, id and secret are base32
// word characters). The three capture groups are kind, id, and secret; the
// secret is what must never survive in evidence.
//
// We bound the secret to >= 16 word chars so an ordinary identifier like
// "uct_caller_foo_bar" in prose is unlikely to false-match, while the real
// 52-char base32 secret always does. base32 here is RFC4648 (A-Z2-7) but the
// codebase's encoder output is matched by [A-Za-z0-9] which also covers any
// lowercased variants safely.
var tokenRe = regexp.MustCompile(`uct_(join|agent|cli|caller)_([A-Za-z0-9]+)_([A-Za-z0-9]{16,})`)

// RedactSecrets removes plaintext Uncluster token secrets from arbitrary text
// before it is written to evidence (#106, ADR-0009). Caller tokens are durable
// bearer credentials (CONTEXT.md), so /tmp evidence must never contain one —
// but join/agent secrets are scrubbed too (defense in depth).
//
// The kind and id are preserved (useful to correlate which token appeared in
// evidence); only the secret is replaced with "REDACTED". This runs over every
// piece of captured evidence (doctor output, command logs, config dumps) as a
// final pass, so a future check that captures token-bearing content cannot leak.
func RedactSecrets(s string) string {
	return tokenRe.ReplaceAllString(s, "uct_${1}_${2}_REDACTED")
}
