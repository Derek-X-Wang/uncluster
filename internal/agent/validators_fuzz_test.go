package agent

import (
	"net/url"
	"strings"
	"testing"
	"unicode"
)

// FuzzValidateUsername fuzzes the username charset validator (#171). The
// username becomes a filename under the AuthorizedPrincipals directory
// (policy.go writes filepath.Join(dir, username)), so a value the validator
// accepts MUST be safe: no path separators, NUL, whitespace/newline, and not
// "." or ".." — otherwise a Policy could write outside the dir or inject
// directives. The fuzz asserts that safety invariant, not merely no-panic.
func FuzzValidateUsername(f *testing.F) {
	for _, s := range []string{
		"alice", "root", "user-1", "svc_account", "",
		".", "..", "a/b", "a\\b", "a b", "a\nb", "a\rb", "a\tb", "a\x00b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validateUsername(s) != nil {
			return
		}
		if s == "" || s == "." || s == ".." {
			t.Fatalf("validateUsername accepted unsafe username %q", s)
		}
		if strings.ContainsAny(s, "/\\\x00\n\r\t ") {
			t.Fatalf("validateUsername accepted username with a path/injection char: %q", s)
		}
	})
}

// FuzzValidateCallerTokenID fuzzes the caller_token_id charset validator (#171).
// The caller_token_id becomes the cert principal written into an
// AuthorizedPrincipals file (one principal per line); a value the validator
// accepts MUST contain nothing dangerous in that context: no whitespace
// (line/field injection), comma, or glob metacharacters (* ? [ ]).
func FuzzValidateCallerTokenID(f *testing.F) {
	for _, s := range []string{
		"abc123", "CALLERID9", "uct-caller-x", "",
		"a,b", "a*b", "a?b", "a[b", "a]b", "a b", "a\nb", "a\tb",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validateCallerTokenID(s) != nil {
			return
		}
		if s == "" {
			t.Fatalf("validateCallerTokenID accepted the empty id")
		}
		for _, r := range s {
			if unicode.IsSpace(r) || r == ',' || r == '*' || r == '?' || r == '[' || r == ']' {
				t.Fatalf("validateCallerTokenID accepted dangerous char %q in %q", r, s)
			}
		}
	})
}

// FuzzValidateUpdateURL fuzzes the self-update host allowlist check (#171,
// ADR-0006/#39). It is the last-mile defence that keeps a compromised Control
// plane from pointing an Agent at an attacker-hosted binary. The invariant: any
// URL it accepts must resolve to a host that is EXACTLY an allowlist entry
// (case-insensitive) — a non-allowlisted host must never pass.
func FuzzValidateUpdateURL(f *testing.F) {
	for _, s := range []string{
		"https://github.com/x/y", "http://github.com:443/a", "https://GitHub.com/x",
		"https://evil.github.com/x", "https://githubXcom/x", "https://github.com.evil.com/x",
		"", "://", "http://", "not a url", "https://[::1]/x", "file:///etc/passwd",
	} {
		f.Add(s)
	}
	allowlist := []string{"github.com"}
	f.Fuzz(func(t *testing.T, raw string) {
		if ValidateUpdateURL(raw, allowlist) != nil {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("ValidateUpdateURL accepted a URL that url.Parse rejects: %q", raw)
		}
		if host := strings.ToLower(u.Hostname()); host != "github.com" {
			t.Fatalf("ValidateUpdateURL accepted non-allowlisted host %q (raw %q)", host, raw)
		}
	})
}

// FuzzUnmarshalDesiredState fuzzes the Windows spool desired-state decoder
// (#171). The LocalSystem principals-writer reads this from an untrusted spool
// across a privilege boundary (ADR-0004 role-split), so a malformed payload
// must yield a clean error, never a panic. When it does parse, re-marshalling
// and re-parsing must be stable (no decode asymmetry the writer could act on
// inconsistently).
func FuzzUnmarshalDesiredState(f *testing.F) {
	f.Add([]byte(`{"version":1,"hash":"blake3:ab","principals":[{"username":"alice","caller_token_ids":["x"]}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"version":"notanint"}`))
	f.Add([]byte(`{"version":1e9}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`{"principals":[{"username":"../../etc","caller_token_ids":["a\nb"]}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := unmarshalDesiredState(b)
		if err != nil {
			return
		}
		rb, merr := marshalDesiredState(d)
		if merr != nil {
			t.Fatalf("marshal of a parsed desired-state failed: %v (input %q)", merr, b)
		}
		if _, uerr := unmarshalDesiredState(rb); uerr != nil {
			t.Fatalf("re-unmarshal of a marshalled desired-state failed: %v (input %q)", uerr, b)
		}
	})
}
