package validate

import (
	"strings"
	"testing"
)

// TestRedactSecrets is the load-bearing security test for #106: evidence
// written to /tmp must NEVER contain a plaintext Caller token (a durable bearer
// credential per CONTEXT.md). Tokens have the form uct_<kind>_<id>_<secret>
// (internal/token); redaction scrubs the secret on every kind, not just
// "caller", because join/agent secrets are sensitive too.
func TestRedactSecrets(t *testing.T) {
	const callerTok = "uct_caller_k4m8j3x2abcd1234_9f2a7b1c4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e"

	t.Run("caller token secret is scrubbed", func(t *testing.T) {
		in := "Authorization: Bearer " + callerTok + "\n"
		out := RedactSecrets(in)
		if strings.Contains(out, callerTok) {
			t.Fatalf("redaction left the full caller token intact:\n%s", out)
		}
		// The secret tail must be gone entirely.
		if strings.Contains(out, "9f2a7b1c4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e") {
			t.Errorf("redaction left the secret tail in the output:\n%s", out)
		}
		// Some redaction marker should remain so evidence shows a token WAS there.
		if !strings.Contains(out, "REDACTED") {
			t.Errorf("expected a REDACTED marker, got:\n%s", out)
		}
	})

	t.Run("all kinds scrubbed", func(t *testing.T) {
		for _, kind := range []string{"caller", "join", "agent", "cli"} {
			tok := "uct_" + kind + "_id000000000000_secretsecretsecretsecretsecretsecretsecretsecret00"
			out := RedactSecrets("token=" + tok)
			if strings.Contains(out, "secretsecret") {
				t.Errorf("kind %q: secret not scrubbed: %s", kind, out)
			}
		}
	})

	t.Run("multiple tokens in one blob all scrubbed", func(t *testing.T) {
		in := callerTok + " then some text then uct_join_aaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb end"
		out := RedactSecrets(in)
		if strings.Contains(out, "9f2a7b1c4d5e") || strings.Contains(out, "bbbbbbbbbbbbbbbb") {
			t.Errorf("not all tokens scrubbed:\n%s", out)
		}
	})

	t.Run("non-token text is untouched", func(t *testing.T) {
		in := "sshd is running; principals dir ok at /etc/ssh/auth_principals (root:uncluster 0775)"
		if got := RedactSecrets(in); got != in {
			t.Errorf("redaction altered non-secret text:\n in: %q\nout: %q", in, got)
		}
	})

	t.Run("token id may be preserved for debuggability but secret never", func(t *testing.T) {
		// We allow the kind+id to survive (useful to correlate which token),
		// but assert the secret portion is always gone.
		out := RedactSecrets(callerTok)
		if strings.Contains(out, "_9f2a7b1c") {
			t.Errorf("secret must not survive in any form: %s", out)
		}
	})
}
