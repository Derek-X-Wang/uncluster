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
	"io"
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
//
// ============================================================================
// FUTURE-READER STOP SIGN — DO NOT SIMPLIFY THIS LOAD PATH (#48)
// ============================================================================
//
// What this protects: the CA private key is the highest-value secret in the
// entire system. Whoever holds it can forge any SSH certificate as any user
// for any Agent. Compromise = total system takeover. There is no rotation
// flow today (deferred per ADR-0005), so the at-rest file is the entire
// trust anchor for the V2 lifetime of a deployment.
//
// What the code below defends against:
//
//  1. TOCTOU (Time-Of-Check / Time-Of-Use) on the file.
//     Pre-fix shape was `os.Stat(path) → checkFileACL(path) → os.ReadFile(path)`.
//     Each call re-resolves the path. An attacker with write access to the
//     parent directory can swap the file (rename, unlink+recreate) between
//     the perm-check and the read. We instead open exactly ONCE, then call
//     `f.Stat()` on the open fd to read mode bits — the fd is bound to the
//     inode of the file we'll read, so the check and the read can no longer
//     diverge.
//
//  2. Symlink follow.
//     Even without a race, a pre-planted symlink at `path` pointing at
//     attacker-controlled bytes would defeat any path-based check. We use
//     `O_NOFOLLOW` (Unix) so the open fails with ELOOP if `path` is a
//     symlink. On Windows the file-level DACL (SYSTEM + Administrators
//     only) is the equivalent guard.
//
//  3. Loose parent directory.
//     A 0600 file inside a 0755 directory is still replaceable by anyone
//     with write access to that directory. Critically, `MkdirAll(dir, 0o700)`
//     does NOT chmod a pre-existing directory — if the dir was created
//     before bootstrap by an installer or stray `mkdir`, it keeps its
//     looser mode and silently undermines the file-level protection. We
//     verify the parent dir's mode is 0700 AND that its owner is the
//     current process's effective UID; refuse to load otherwise.
//
// FORBIDDEN shapes — DO NOT replace this function with any of:
//   - `os.ReadFile(path)` alone (no perm check, no symlink defense).
//   - `os.Stat(path) → checkFileACL(path) → os.ReadFile(path)` (the original
//     racy shape — three separate name lookups, file checked is not
//     necessarily the file read).
//   - Any shape that calls `os.Stat(path)` or `checkFileACL(path)` BEFORE
//     opening the file. The fd-stat is authoritative; path-based checks
//     are advisory only.
//
// References:
//   - ADR-0001 — why the CA matters (cert authority trust model).
//   - ADR-0005 — CA key at-rest threat model (operator responsibility scope).
//   - Issue #48 — original TOCTOU report and operator triage rationale.
//   - Issue #38 / PR #52 — companion `safewrite_*.go` hardening (write side).
//
// The happy path (bootstrap-created 0700 dir owned by the process user,
// 0600 regular file, no symlinks) loads in a single call with no operator-
// visible change. Validation failures return errors that name what failed
// so the operator can diagnose without strace.
// ============================================================================
func LoadPrivateFromDisk(path string) (ssh.Signer, error) {
	// (1) Validate the parent directory FIRST. If the directory is loose
	// or owned by someone else, refuse — even opening a file inside an
	// untrusted directory is a TOCTOU-prone proposition.
	if err := checkParentDirSafe(path); err != nil {
		return nil, err
	}

	// (2) Open the file ONCE with O_NOFOLLOW (Unix; symlink → ELOOP).
	// All subsequent checks operate on this fd, NOT the path.
	f, err := openReadOnlyNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("ca: open %s: %w", path, err)
	}
	defer f.Close()

	// (3) Validate mode bits FROM THE OPEN FD. This is the TOCTOU-proof
	// part: a path-based stat could be looking at a different inode by
	// now, but f.Stat() returns the metadata of the file we hold open
	// and are about to read.
	if err := checkFileModeFromFD(f); err != nil {
		return nil, err
	}

	// (4) Defense-in-depth: also run the existing path-based ACL check.
	// On Windows this is the authoritative DACL check (since POSIX mode
	// bits don't gate NTFS access). On Unix it's redundant with (3) but
	// catches any future regression in checkFileModeFromFD. Cheap.
	if err := checkFileACL(path); err != nil {
		return nil, err
	}

	// (5) Read from the open fd — NEVER re-open by path. ReadAll consumes
	// the file we already validated.
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("ca: read %s: %w", path, err)
	}
	return ParsePrivate(data)
}

// WritePrivateToDisk writes marshaled private-key bytes to path with mode 0600.
//
// Symlink-attack hardened (issue #38):
//   - Uses O_CREATE|O_EXCL (plus O_NOFOLLOW on Unix) so the syscall fails
//     atomically if any entry — file, dir, or symlink — already exists at path.
//     Previously os.Stat+WriteFile let a dangling symlink redirect the write.
//   - Refuses to write into a parent directory whose POSIX mode permits
//     group/world access (a 0o600 file in a 0o755 dir is still replaceable
//     by an attacker who controls the dir). MkdirAll(0o700) still creates the
//     dir fresh if absent.
//   - On Windows, parent-dir POSIX mode is meaningless; the DACL applied to
//     the file via restrictFileACL is what restricts access.
func WritePrivateToDisk(path string, marshaled []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ca: mkdir %s: %w", dir, err)
	}
	if err := ensureTightDir(dir); err != nil {
		return err
	}
	// O_CREATE|O_EXCL: atomic create-or-fail. If anything already exists at
	// path — regular file, directory, or symlink — Open fails with ErrExist.
	// O_NOFOLLOW (Unix) makes the failure unambiguous even if a race plants a
	// symlink between MkdirAll and Open.
	f, err := openExclusiveNoFollow(path, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("ca: %s already exists; refusing to overwrite", path)
		}
		return fmt.Errorf("ca: open %s: %w", path, err)
	}
	if _, werr := f.Write(marshaled); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("ca: write %s: %w", path, werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("ca: close %s: %w", path, cerr)
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
