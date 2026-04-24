package token_test

import (
	"strings"
	"testing"

	"github.com/derek-x-wang/uncluster/internal/token"
)

func TestGenerateAndParseRoundTrip(t *testing.T) {
	for _, kind := range []token.Kind{token.KindJoin, token.KindAgent, token.KindCLI} {
		tok, err := token.Generate(kind)
		if err != nil {
			t.Fatalf("Generate(%s): %v", kind, err)
		}
		if !strings.HasPrefix(tok.String(), "uct_"+string(kind)+"_") {
			t.Fatalf("prefix mismatch: %s", tok.String())
		}
		parsed, err := token.Parse(tok.String())
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if parsed.Kind != kind {
			t.Errorf("kind: got %s want %s", parsed.Kind, kind)
		}
		if parsed.ID != tok.ID {
			t.Errorf("id: got %s want %s", parsed.ID, tok.ID)
		}
		if parsed.Secret != tok.Secret {
			t.Errorf("secret: got %s want %s", parsed.Secret, tok.Secret)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"uct_cli_",
		"uct_cli_abc",
		"uct_cli_abc_",
		"uct_xyz_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"not_a_token_at_all",
	}
	for _, c := range cases {
		if _, err := token.Parse(c); err == nil {
			t.Errorf("Parse(%q) should have failed", c)
		}
	}
}

func TestHashAndVerify(t *testing.T) {
	tok, err := token.Generate(token.KindAgent)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := token.HashSecret(tok.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if hash == tok.Secret {
		t.Fatal("hash must not equal plaintext secret")
	}
	ok, err := token.VerifySecret(tok.Secret, hash)
	if err != nil || !ok {
		t.Fatalf("VerifySecret(correct): ok=%v err=%v", ok, err)
	}
	ok, err = token.VerifySecret("wrong-secret", hash)
	if err != nil {
		t.Fatalf("VerifySecret(wrong) err: %v", err)
	}
	if ok {
		t.Fatal("VerifySecret(wrong) returned true")
	}
}

func TestIDLength(t *testing.T) {
	tok, err := token.Generate(token.KindCLI)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.ID) != 16 {
		t.Fatalf("ID length: got %d want 16 (%q)", len(tok.ID), tok.ID)
	}
}

func TestGenerateRejectsInvalidKind(t *testing.T) {
	if _, err := token.Generate(token.Kind("bogus")); err == nil {
		t.Fatal("Generate(bogus) should fail")
	}
}

func TestParseRejectsBadCharset(t *testing.T) {
	// id field contains '_' which isn't in base32's alphabet.
	bad := "uct_cli_aaaaaaaaaaaaaaaa_bb__bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := token.Parse(bad); err == nil {
		t.Fatal("Parse should reject non-base32 chars in id/secret")
	}
}

func TestVerifySecretRejectsMalformedHash(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$argon2id$bad",
		"$argon2i$v=19$m=65536,t=3,p=2$AAAA$BBBB",          // wrong kind
		"$argon2id$v=16$m=65536,t=3,p=2$AAAA$BBBB",         // wrong version
		"PREFIX$argon2id$v=19$m=65536,t=3,p=2$AAAA$BBBB",   // parts[0] != ""
	}
	for _, c := range cases {
		_, err := token.VerifySecret("whatever", c)
		if err == nil {
			t.Errorf("VerifySecret(%q) should return an error", c)
		}
	}
}
