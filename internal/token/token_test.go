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
