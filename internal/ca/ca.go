// Package ca is the Uncluster Control plane's SSH certificate authority.
//
// V2 model (ADR-0001): the Control plane signs short-lived OpenSSH user
// certificates over Callers' existing SSH public keys. Each Agent's sshd
// trusts the CA pubkey via TrustedUserCAKeys and gates login by principal
// lookup in AuthorizedPrincipalsFile.
//
// This package owns:
//   - CA keypair generation (ed25519)
//   - Marshal/parse to OpenSSH-compatible PEM private + authorized_keys public
//   - On-disk read/write with mode discipline (0600 private, 0644 public)
//   - Cert signing with the canonical KeyID audit format
//
// Loading the CA refuses any private-key file with group or world permission
// bits set. Writing refuses to overwrite an existing private key.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Generate returns a fresh ed25519 CA keypair.
func Generate() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate ed25519: %w", err)
	}
	return priv, pub, nil
}

// MarshalPrivate renders an ed25519 private key as an OpenSSH-format PEM block.
// The comment "uncluster-ca" is embedded in the OpenSSH key envelope.
func MarshalPrivate(priv ed25519.PrivateKey) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(priv, "uncluster-ca")
	if err != nil {
		return nil, fmt.Errorf("ca: marshal private: %w", err)
	}
	return pem.EncodeToMemory(block), nil
}

// MarshalPublic renders an ed25519 public key as a single authorized_keys line
// (e.g. "ssh-ed25519 AAAA... uncluster-ca\n").
func MarshalPublic(pub ed25519.PublicKey) ([]byte, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: build public key: %w", err)
	}
	return ssh.MarshalAuthorizedKey(sshPub), nil
}

// ParsePrivate parses an OpenSSH PEM private key.
func ParsePrivate(data []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("ca: parse private: %w", err)
	}
	return signer, nil
}

// LoadPrivateFromDisk reads the CA private key at path and returns a Signer.
// On Unix: refuses the file if its POSIX mode has any group or world bits set.
// On Windows: checks the DACL via GetNamedSecurityInfo; refuses if the file is
// accessible to accounts other than SYSTEM and Administrators.
func LoadPrivateFromDisk(path string) (ssh.Signer, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("ca: stat %s: %w", path, err)
	}
	if err := checkFileACL(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca: read %s: %w", path, err)
	}
	return ParsePrivate(data)
}

// WritePrivateToDisk writes marshaled private-key bytes to path with mode 0600.
// Refuses to overwrite an existing file (so re-bootstrap is safe).
// On Unix: mode 0600 is applied at write time.
// On Windows: mode 0600 is set (no-op on Windows filesystem), then
// restrictFileACL applies a DACL restricting access to SYSTEM + Administrators.
func WritePrivateToDisk(path string, marshaled []byte) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("ca: %s already exists; refusing to overwrite", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ca: stat %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("ca: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, marshaled, 0o600); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	// On Windows, apply DACL to restrict to SYSTEM + Administrators only.
	if err := restrictFileACL(path); err != nil {
		return fmt.Errorf("ca: set file ACL %s: %w", path, err)
	}
	return nil
}

// WritePublicToDisk writes the public key to path with mode 0644 (overwrites).
func WritePublicToDisk(path string, marshaled []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("ca: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, marshaled, 0o644); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	return nil
}

// SignCertParams are the inputs to Sign.
type SignCertParams struct {
	// UserPublicKey is the raw authorized_keys-format pubkey of the Caller.
	// A certificate passed here will be rejected (cert pubkeys are not signable).
	UserPublicKey []byte

	// Principals on the issued cert. Convention: single element = Caller token ID.
	Principals []string

	// KeyID is the audit-shaped handle (use FormatKeyID).
	KeyID string

	// ValidAfter / ValidBefore bound the cert validity window. Callers should
	// set ValidAfter = now - 30s for clock skew defense.
	ValidAfter  time.Time
	ValidBefore time.Time

	// Serial is the cert serial number (typically a monotonic counter, but any
	// non-zero u64 works for V2 since revocation by serial is not yet implemented).
	Serial uint64
}

// Sign produces an OpenSSH user certificate signed by the given CA.
// Returns the cert in authorized_keys form (ready to write next to the user's
// private key as <key>-cert.pub).
func Sign(caSigner ssh.Signer, p SignCertParams) ([]byte, error) {
	userKey, _, _, _, err := ssh.ParseAuthorizedKey(p.UserPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ca: parse user pubkey: %w", err)
	}
	if strings.Contains(userKey.Type(), "cert-v01@openssh.com") {
		return nil, errors.New("ca: input is itself a certificate; only raw user pubkeys can be signed")
	}
	if !p.ValidBefore.After(p.ValidAfter) {
		return nil, errors.New("ca: ValidBefore must be strictly after ValidAfter")
	}
	if len(p.Principals) == 0 {
		return nil, errors.New("ca: at least one principal required")
	}
	if p.KeyID == "" {
		return nil, errors.New("ca: KeyID required (use FormatKeyID)")
	}

	cert := &ssh.Certificate{
		Key:             userKey,
		Serial:          p.Serial,
		CertType:        ssh.UserCert,
		KeyId:           p.KeyID,
		ValidPrincipals: p.Principals,
		ValidAfter:      uint64(p.ValidAfter.Unix()),
		ValidBefore:     uint64(p.ValidBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-pty":     "",
				"permit-user-rc": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("ca: sign cert: %w", err)
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

// FormatKeyID builds the canonical audit-shaped KeyID:
//
//	uncluster:<request_id>:caller=<caller_token_id>:agent=<agent_id>:user=<unix_username>
//
// Callers must ensure components do not contain ':' (validated upstream when
// parsing user input or agent/caller IDs).
func FormatKeyID(requestID, callerID, agentID, username string) string {
	return fmt.Sprintf("uncluster:%s:caller=%s:agent=%s:user=%s", requestID, callerID, agentID, username)
}
