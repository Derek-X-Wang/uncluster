// Package token defines Uncluster's token format and verification primitives.
//
// Token string: uct_<kind>_<id>_<secret>
//   - kind:   "join" | "agent" | "cli"
//   - id:     16 base32 chars (80 bits). Public lookup key.
//   - secret: 52 base32 chars (~256 bits). Only argon2id(secret) is stored.
package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Kind string

const (
	KindJoin  Kind = "join"
	KindAgent Kind = "agent"
	KindCLI   Kind = "cli"

	idLen     = 16 // base32 chars
	secretLen = 52 // base32 chars
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type Token struct {
	Kind   Kind
	ID     string
	Secret string
}

func (t Token) String() string {
	return fmt.Sprintf("uct_%s_%s_%s", t.Kind, t.ID, t.Secret)
}

// Generate produces a fresh token of the given kind.
func Generate(kind Kind) (Token, error) {
	if !validKind(kind) {
		return Token{}, fmt.Errorf("invalid kind %q", kind)
	}
	id, err := randBase32(10) // 10 bytes → 16 base32 chars
	if err != nil {
		return Token{}, fmt.Errorf("generate id: %w", err)
	}
	sec, err := randBase32(32) // 32 bytes → 52 base32 chars exactly
	if err != nil {
		return Token{}, fmt.Errorf("generate secret: %w", err)
	}
	return Token{Kind: kind, ID: id, Secret: sec}, nil
}

// Parse extracts the three components. Rejects malformed strings.
func Parse(s string) (Token, error) {
	const prefix = "uct_"
	if !strings.HasPrefix(s, prefix) {
		return Token{}, errors.New("token: missing uct_ prefix")
	}
	rest := s[len(prefix):]
	parts := strings.SplitN(rest, "_", 3)
	if len(parts) != 3 {
		return Token{}, errors.New("token: wrong segment count")
	}
	kind := Kind(parts[0])
	if !validKind(kind) {
		return Token{}, fmt.Errorf("token: unknown kind %q", kind)
	}
	if len(parts[1]) != idLen {
		return Token{}, fmt.Errorf("token: id length %d want %d", len(parts[1]), idLen)
	}
	if len(parts[2]) != secretLen {
		return Token{}, fmt.Errorf("token: secret length %d want %d", len(parts[2]), secretLen)
	}
	if _, err := b32.DecodeString(parts[1]); err != nil {
		return Token{}, fmt.Errorf("token: id contains non-base32 characters")
	}
	if _, err := b32.DecodeString(parts[2]); err != nil {
		return Token{}, fmt.Errorf("token: secret contains non-base32 characters")
	}
	return Token{Kind: kind, ID: parts[1], Secret: parts[2]}, nil
}

// HashSecret produces an argon2id hash string of a token secret, suitable for DB storage.
func HashSecret(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("hash salt: %w", err)
	}
	// Parameters: time=3, memory=64 MiB, parallelism=2, 32-byte key.
	const timeCost, memoryCost, parallelism, keyLen = 3, 64 * 1024, 2, 32
	key := argon2.IDKey([]byte(secret), salt, timeCost, memoryCost, parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memoryCost, timeCost, parallelism,
		b32.EncodeToString(salt), b32.EncodeToString(key)), nil
}

// VerifySecret compares a plaintext secret against a stored argon2id hash.
func VerifySecret(secret, stored string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, fmt.Errorf("token: verify malformed hash")
	}
	var m, t, p int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, fmt.Errorf("token: verify params: %w", err)
	}
	salt, err := b32.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("token: verify salt: %w", err)
	}
	want, err := b32.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("token: verify key: %w", err)
	}
	got := argon2.IDKey([]byte(secret), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func randBase32(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

func validKind(k Kind) bool {
	switch k {
	case KindJoin, KindAgent, KindCLI:
		return true
	}
	return false
}
