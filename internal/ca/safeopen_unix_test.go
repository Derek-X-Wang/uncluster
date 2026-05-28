//go:build !windows

package ca

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// mustMarshalAuthorizedPub returns the canonical authorized_keys-line
// fingerprint for the given ed25519 private key. Used as a tamper-
// resistant identity for "the signer matches THIS key, not the
// attacker's key."
func mustMarshalAuthorizedPub(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(pub))
}

// mustMarshalSignerAuthorizedPub returns the authorized_keys-line for
// a Signer (post-load). Comparing the two strings tells us whether
// LoadPrivateFromDisk returned the canonical key or something else.
func mustMarshalSignerAuthorizedPub(t *testing.T, s ssh.Signer) string {
	t.Helper()
	return string(ssh.MarshalAuthorizedKey(s.PublicKey()))
}

// Compatibility aliases used by the table-style assertions below. Kept
// out of the helper bodies above so the call sites read fluently.
func MustMarshalAuthorizedPub(t *testing.T, priv ed25519.PrivateKey) string {
	return mustMarshalAuthorizedPub(t, priv)
}
func MustMarshalSignerAuthorizedPub(t *testing.T, s ssh.Signer) string {
	return mustMarshalSignerAuthorizedPub(t, s)
}

// writeKeyInTightDir is a test helper: creates a 0700 dir owned by the
// current user, writes a freshly-generated CA private key at 0600
// inside it, and returns the path. Used as the happy-path setup for
// the load-side tests below.
func writeKeyInTightDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod 0700 parent: %v", err)
	}
	priv, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bytes, err := MarshalPrivate(priv)
	if err != nil {
		t.Fatalf("MarshalPrivate: %v", err)
	}
	path := filepath.Join(dir, "ca")
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// TestLoadPrivate_HappyPath confirms the post-#48 hardened load path
// is still a single-call success for the canonical bootstrap shape:
// 0700 dir owned by the process user, 0600 regular file.
func TestLoadPrivate_HappyPath(t *testing.T) {
	path := writeKeyInTightDir(t)
	if _, err := LoadPrivateFromDisk(path); err != nil {
		t.Errorf("LoadPrivateFromDisk: %v", err)
	}
}

// TestLoadPrivate_RejectsLooseParentDir covers acceptance bullet "dir
// mode 0755 rejected". This is the gap the original Stat-Stat-Read
// shape missed entirely: a 0600 file in a 0755 dir is replaceable by
// anyone with write access to the dir.
func TestLoadPrivate_RejectsLooseParentDir(t *testing.T) {
	path := writeKeyInTightDir(t)
	// Loosen the parent — file mode stays 0600.
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateFromDisk(path); err == nil {
		t.Error("expected refusal for parent dir mode 0755")
	}
}

// TestLoadPrivate_RejectsSymlink covers "file is a symlink → rejected".
// Plant a symlink at the canonical CA path pointing at an arbitrary
// attacker-controlled file inside the same (tight) dir. The original
// shape would happily follow it (Stat resolves symlinks).
func TestLoadPrivate_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	priv, _, _ := Generate()
	keyBytes, _ := MarshalPrivate(priv)

	target := filepath.Join(dir, "real-key")
	if err := os.WriteFile(target, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "ca")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := LoadPrivateFromDisk(link)
	if err == nil {
		t.Error("expected refusal when CA path is a symlink (would defeat path-based perm checks)")
	}
}

// TestLoadPrivate_RejectsFileMode0644 covers acceptance bullet "file
// with mode 0644 → rejected". This is the existing perm-check
// behaviour, restated to confirm the fd-based check (replacing the
// path-based Stat) still catches it.
func TestLoadPrivate_RejectsFileMode0644(t *testing.T) {
	path := writeKeyInTightDir(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateFromDisk(path); err == nil {
		t.Error("expected refusal for 0644 file mode")
	}
}

// TestLoadPrivate_MissingFile covers "missing file → existing error
// path unchanged" — i.e. operators get a useful ENOENT-shaped error,
// not a confusing perm-related one.
func TestLoadPrivate_MissingFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nonexistent")
	if _, err := LoadPrivateFromDisk(missing); err == nil {
		t.Error("expected error for missing file")
	}
}

// TestLoadPrivate_RaceSwap is the integration test the brief calls out:
// while one goroutine repeatedly calls LoadPrivateFromDisk, another swaps
// the file via rename. Verify the loader either returns the correct
// content OR a clean error — never returns attacker-controlled bytes
// as a valid Signer.
//
// Note: with the fix in place, this test will mostly see either:
//   - the original key load successfully (open won first), or
//   - an ENOENT-shaped error (rename won first; open failed).
//
// What we are guarding against: a regressed loader that returned bytes
// from a file other than the one it perm-checked. The check is on the
// SIGNER: any signer returned must equal-public-key the canonical key,
// because we never plant a second valid CA key — only attacker-
// crafted junk that would parse-fail or short-circuit at the perm check.
func TestLoadPrivate_RaceSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("race test uses Unix rename semantics")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	priv, _, _ := Generate()
	keyBytes, _ := MarshalPrivate(priv)
	canonical := MustMarshalAuthorizedPub(t, priv) // for fingerprint comparison

	path := filepath.Join(dir, "ca")
	if err := os.WriteFile(path, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// Attacker file: junk bytes (would parse-fail if accidentally
	// returned). Also at 0600 so the fd-mode check passes IF the
	// regressed loader opens this file by accident.
	attackerPath := filepath.Join(dir, "ca.attacker")
	if err := os.WriteFile(attackerPath, []byte("not a real private key"), 0o600); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// Alternate which file lives at `path`.
				_ = os.Rename(path, path+".tmp")
				_ = os.Rename(attackerPath, path)
				_ = os.Rename(path+".tmp", attackerPath)
			}
		}
	}()

	// Run the loader many times. Any signer it returns must match the
	// canonical key. Any error is acceptable (ENOENT / parse failure /
	// loose-perm rejection are all benign outcomes of the race).
	for i := 0; i < 200; i++ {
		signer, err := LoadPrivateFromDisk(path)
		if err != nil {
			continue
		}
		got := MustMarshalSignerAuthorizedPub(t, signer)
		if got != canonical {
			t.Fatalf("race produced attacker-controlled signer at iteration %d", i)
		}
	}
	close(stop)
	wg.Wait()
}
