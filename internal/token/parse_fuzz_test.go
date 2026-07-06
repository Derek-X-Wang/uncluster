package token

import (
	"strings"
	"testing"
)

// FuzzParse fuzzes Caller/bearer token parsing (#171). Parse gates the bearer
// credential format; a malformed token must produce a clean error, never a
// panic. The load-bearing invariant: any string Parse accepts must round-trip
// byte-exactly through Token.String(), so a parsed token can never silently
// differ from the credential the client presented.
func FuzzParse(f *testing.F) {
	// Seeds: a valid caller/join token, plus known-tricky malformed shapes.
	f.Add("uct_caller_" + strings.Repeat("A", idLen) + "_" + strings.Repeat("A", secretLen))
	f.Add("uct_join_" + strings.Repeat("B", idLen) + "_" + strings.Repeat("C", secretLen))
	f.Add("")
	f.Add("uct_")
	f.Add("uct_caller__")
	f.Add("uct_bogus_" + strings.Repeat("A", idLen) + "_" + strings.Repeat("A", secretLen)) // bad kind
	f.Add("uct_caller_" + strings.Repeat("1", idLen) + "_" + strings.Repeat("A", secretLen)) // '1' not base32
	f.Add("uct_caller_" + strings.Repeat("A", idLen-1) + "_" + strings.Repeat("A", secretLen)) // short id
	f.Add("uct_caller_" + strings.Repeat("A", idLen) + "_" + strings.Repeat("A", secretLen) + "_x") // extra segment folded into secret
	f.Add("notatoken")

	f.Fuzz(func(t *testing.T, s string) {
		tok, err := Parse(s)
		if err != nil {
			return
		}
		// A successfully parsed token must reconstruct the exact input.
		if got := tok.String(); got != s {
			t.Fatalf("round-trip mismatch: Parse(%q).String() = %q", s, got)
		}
		// And it must be a known kind with the fixed-length id/secret Parse enforces.
		if !validKind(tok.Kind) {
			t.Fatalf("Parse accepted unknown kind %q", tok.Kind)
		}
		if len(tok.ID) != idLen || len(tok.Secret) != secretLen {
			t.Fatalf("Parse accepted bad lengths: id=%d secret=%d", len(tok.ID), len(tok.Secret))
		}
	})
}
