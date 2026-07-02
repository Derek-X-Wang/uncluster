package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestSignInputErrorsAreErrInvalidInput pins the CA→handler contract (#142):
// every input-validation failure in Sign wraps ErrInvalidInput, so the
// cert-signing handler classifies 400 vs 500 with errors.Is instead of
// substring-matching the message text. A future message reword must not
// silently reclassify a 400 as a 500 (or vice-versa).
func TestSignInputErrorsAreErrInvalidInput(t *testing.T) {
	caPriv, _, _ := Generate()
	caSigner, err := makeSigner(caPriv)
	if err != nil {
		t.Fatal(err)
	}

	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshUserPub, _ := ssh.NewPublicKey(userPub)
	goodPubBytes := ssh.MarshalAuthorizedKey(sshUserPub)
	now := time.Now()

	// A valid cert to feed back as (rejected) input for the cert-as-pubkey case.
	certBytes, err := Sign(caSigner, SignCertParams{
		UserPublicKey: goodPubBytes,
		Principals:    []string{"x"},
		KeyID:         FormatKeyID("r", "c", "a", "u"),
		ValidAfter:    now,
		ValidBefore:   now.Add(time.Minute),
		Serial:        1,
	})
	if err != nil {
		t.Fatalf("Sign (setup): %v", err)
	}

	cases := []struct {
		name string
		p    SignCertParams
	}{
		{
			name: "malformed pubkey",
			p: SignCertParams{
				UserPublicKey: []byte("not-a-real-key"),
				Principals:    []string{"x"}, KeyID: "k",
				ValidAfter: now, ValidBefore: now.Add(time.Minute), Serial: 1,
			},
		},
		{
			name: "cert-as-pubkey",
			p: SignCertParams{
				UserPublicKey: certBytes,
				Principals:    []string{"x"}, KeyID: "k",
				ValidAfter: now, ValidBefore: now.Add(time.Minute), Serial: 2,
			},
		},
		{
			name: "invalid validity window",
			p: SignCertParams{
				UserPublicKey: goodPubBytes,
				Principals:    []string{"x"}, KeyID: "k",
				ValidAfter: now.Add(time.Minute), ValidBefore: now, Serial: 3,
			},
		},
		{
			name: "missing principal",
			p: SignCertParams{
				UserPublicKey: goodPubBytes,
				Principals:    nil, KeyID: "k",
				ValidAfter: now, ValidBefore: now.Add(time.Minute), Serial: 4,
			},
		},
		{
			name: "missing keyid",
			p: SignCertParams{
				UserPublicKey: goodPubBytes,
				Principals:    []string{"x"}, KeyID: "",
				ValidAfter: now, ValidBefore: now.Add(time.Minute), Serial: 5,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Sign(caSigner, tc.p)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("%s: errors.Is(err, ErrInvalidInput) = false; err = %v", tc.name, err)
			}
		})
	}

	// A successful sign must NOT be classified as invalid input.
	if _, err := Sign(caSigner, SignCertParams{
		UserPublicKey: goodPubBytes,
		Principals:    []string{"x"}, KeyID: "k",
		ValidAfter: now, ValidBefore: now.Add(time.Minute), Serial: 6,
	}); err != nil {
		t.Fatalf("valid sign returned error: %v", err)
	}
}
