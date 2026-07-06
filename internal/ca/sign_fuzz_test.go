package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// FuzzSign fuzzes ca.Sign over arbitrary Caller public-key bytes (#171). Sign
// guards POST /v1/certs: it parses attacker-influenced authorized_keys bytes
// (the Caller's pubkey) before minting a certificate. Malformed pubkey bytes
// must produce a clean error (ErrInvalidInput), never a panic — and whenever
// Sign DOES return a certificate, that output must parse back as a valid
// OpenSSH certificate (never a raw key or corrupt blob).
func FuzzSign(f *testing.F) {
	// A valid raw user pubkey seed, plus malformed shapes.
	if _, userPriv, err := ed25519.GenerateKey(rand.Reader); err == nil {
		if userSigner, err := ssh.NewSignerFromSigner(userPriv); err == nil {
			f.Add(ssh.MarshalAuthorizedKey(userSigner.PublicKey()))
		}
	}
	f.Add([]byte("ssh-ed25519 AAAAnotbase64 comment"))
	f.Add([]byte(""))
	f.Add([]byte("garbage"))
	f.Add([]byte("ssh-rsa"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----"))

	// One CA signer for the whole run (the CA key is not the fuzzed input).
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromSigner(caPriv)
	if err != nil {
		f.Fatalf("build CA signer: %v", err)
	}

	f.Fuzz(func(t *testing.T, pub []byte) {
		out, err := Sign(caSigner, SignCertParams{
			UserPublicKey: pub,
			Principals:    []string{"caller-x"},
			KeyID:         FormatKeyID("req", "callerx", "agenty", "userz"),
			ValidAfter:    time.Unix(1000, 0),
			ValidBefore:   time.Unix(2000, 0),
			Serial:        1,
		})
		if err != nil {
			return // a bad pubkey is a clean rejection, as intended.
		}
		parsed, _, _, _, perr := ssh.ParseAuthorizedKey(out)
		if perr != nil {
			t.Fatalf("Sign produced unparseable output for pubkey %q: %v", pub, perr)
		}
		if _, ok := parsed.(*ssh.Certificate); !ok {
			t.Fatalf("Sign output is not a certificate (%T) for pubkey %q", parsed, pub)
		}
	})
}
