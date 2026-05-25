package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestGenerateProducesKeypair(t *testing.T) {
	priv, pub, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("priv size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("pub size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	// Pub matches priv's derived pub.
	if !pubMatchesPriv(pub, priv) {
		t.Error("pub does not match priv-derived pub")
	}
}

func TestPrivateRoundTrip(t *testing.T) {
	priv, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	marshaled, err := MarshalPrivate(priv)
	if err != nil {
		t.Fatalf("MarshalPrivate: %v", err)
	}
	if !strings.Contains(string(marshaled), "OPENSSH PRIVATE KEY") {
		t.Errorf("marshaled does not look like OpenSSH PEM:\n%s", marshaled)
	}
	signer, err := ParsePrivate(marshaled)
	if err != nil {
		t.Fatalf("ParsePrivate: %v", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("type = %s, want %s", signer.PublicKey().Type(), ssh.KeyAlgoED25519)
	}
}

func TestSignProducesParseableCert(t *testing.T) {
	caPriv, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate ca: %v", err)
	}
	caSigner, err := makeSigner(caPriv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}

	// User keypair the cert will be issued over.
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("user keypair: %v", err)
	}
	sshUserPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	userPubBytes := ssh.MarshalAuthorizedKey(sshUserPub)

	now := time.Now()
	keyID := FormatKeyID("req_001", "caller_k4m8j3x2", "ag_01J", "derek")
	certBytes, err := Sign(caSigner, SignCertParams{
		UserPublicKey: userPubBytes,
		Principals:    []string{"caller_k4m8j3x2"},
		KeyID:         keyID,
		ValidAfter:    now.Add(-30 * time.Second),
		ValidBefore:   now.Add(5 * time.Minute),
		Serial:        42,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed type = %T, want *ssh.Certificate", parsed)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want UserCert", cert.CertType)
	}
	if cert.KeyId != keyID {
		t.Errorf("KeyId = %q, want %q", cert.KeyId, keyID)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "caller_k4m8j3x2" {
		t.Errorf("ValidPrincipals = %v", cert.ValidPrincipals)
	}
	if cert.Serial != 42 {
		t.Errorf("Serial = %d, want 42", cert.Serial)
	}

	// Verify CA signature.
	cc := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(caSigner.PublicKey())
		},
	}
	if err := cc.CheckCert("caller_k4m8j3x2", cert); err != nil {
		t.Errorf("CheckCert: %v", err)
	}
}

func TestSignRejectsCertInput(t *testing.T) {
	caPriv, _, _ := Generate()
	caSigner, err := makeSigner(caPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a cert, then try to pass it back as input.
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshUserPub, _ := ssh.NewPublicKey(userPub)
	userPubBytes := ssh.MarshalAuthorizedKey(sshUserPub)
	now := time.Now()
	cert, err := Sign(caSigner, SignCertParams{
		UserPublicKey: userPubBytes,
		Principals:    []string{"x"},
		KeyID:         FormatKeyID("r", "c", "a", "u"),
		ValidAfter:    now,
		ValidBefore:   now.Add(time.Minute),
		Serial:        1,
	})
	if err != nil {
		t.Fatalf("Sign (setup): %v", err)
	}

	_, err = Sign(caSigner, SignCertParams{
		UserPublicKey: cert, // feeding a cert as the user pubkey
		Principals:    []string{"x"},
		KeyID:         FormatKeyID("r2", "c", "a", "u"),
		ValidAfter:    now,
		ValidBefore:   now.Add(time.Minute),
		Serial:        2,
	})
	if err == nil {
		t.Fatal("expected error when feeding a cert as the user pubkey, got nil")
	}
	if !strings.Contains(err.Error(), "itself a certificate") {
		t.Errorf("error = %v; want mention of 'itself a certificate'", err)
	}
}

func TestSignRejectsInvalidWindow(t *testing.T) {
	caPriv, _, _ := Generate()
	caSigner, err := makeSigner(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshUserPub, _ := ssh.NewPublicKey(userPub)
	userPubBytes := ssh.MarshalAuthorizedKey(sshUserPub)

	now := time.Now()
	_, err = Sign(caSigner, SignCertParams{
		UserPublicKey: userPubBytes,
		Principals:    []string{"x"},
		KeyID:         FormatKeyID("r", "c", "a", "u"),
		ValidAfter:    now.Add(time.Minute),
		ValidBefore:   now, // before ValidAfter — reject
		Serial:        1,
	})
	if err == nil {
		t.Fatal("expected error for invalid validity window")
	}
}

func TestSignRequiresPrincipalAndKeyID(t *testing.T) {
	caPriv, _, _ := Generate()
	caSigner, err := makeSigner(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshUserPub, _ := ssh.NewPublicKey(userPub)
	userPubBytes := ssh.MarshalAuthorizedKey(sshUserPub)

	now := time.Now()
	base := SignCertParams{
		UserPublicKey: userPubBytes,
		ValidAfter:    now,
		ValidBefore:   now.Add(time.Minute),
		Serial:        1,
	}

	p := base
	p.KeyID = "k"
	if _, err := Sign(caSigner, p); err == nil {
		t.Error("expected error when Principals empty")
	}

	p = base
	p.Principals = []string{"x"}
	if _, err := Sign(caSigner, p); err == nil {
		t.Error("expected error when KeyID empty")
	}
}

func TestFormatKeyID(t *testing.T) {
	got := FormatKeyID("req_001", "caller_k4", "ag_01J", "derek")
	want := "uncluster:req_001:caller=caller_k4:agent=ag_01J:user=derek"
	if got != want {
		t.Errorf("FormatKeyID = %q, want %q", got, want)
	}
}

func TestWritePrivateRefusesOverwriteAndEnforcesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "ca")
	priv, _, _ := Generate()
	bytes, err := MarshalPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateToDisk(path, bytes); err != nil {
		t.Fatalf("first write: %v", err)
	}
	// Mode enforcement: POSIX mode bits are not enforced on Windows.
	// TODO(S9a): restore this coverage via Windows ACL check.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("file mode = %#o, want 0600", mode)
		}
	}
	// Refuse overwrite — works on all platforms.
	if err := WritePrivateToDisk(path, bytes); err == nil {
		t.Error("expected refusal to overwrite existing CA key")
	}
}

func TestLoadPrivateRejectsLoosePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		// POSIX mode bits are not enforced on Windows; LoadPrivateFromDisk skips
		// the mode check on Windows. ACL-based restriction is deferred to S9a.
		// TODO(S9a): restore via Windows ACL check.
		t.Skip("POSIX mode bits not enforced on Windows; see follow-up for ACL-based check")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ca")
	priv, _, _ := Generate()
	bytes, _ := MarshalPrivate(priv)
	if err := os.WriteFile(path, bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateFromDisk(path); err == nil {
		t.Fatal("expected error for 0644 mode CA file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateFromDisk(path); err != nil {
		t.Errorf("after chmod 0600, expected ok, got %v", err)
	}
}

func TestWritePublicWritesReadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pub")
	_, pub, _ := Generate()
	bytes, err := MarshalPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePublicToDisk(path, bytes); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bytes) {
		t.Errorf("roundtrip mismatch:\nwrote: %q\nread:  %q", bytes, got)
	}
}

// --- helpers ---

func makeSigner(priv ed25519.PrivateKey) (ssh.Signer, error) {
	marshaled, err := MarshalPrivate(priv)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(marshaled)
}

func pubMatchesPriv(pub ed25519.PublicKey, priv ed25519.PrivateKey) bool {
	derived := priv.Public().(ed25519.PublicKey)
	if len(derived) != len(pub) {
		return false
	}
	for i := range pub {
		if pub[i] != derived[i] {
			return false
		}
	}
	return true
}
