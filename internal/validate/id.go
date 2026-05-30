package validate

import (
	"crypto/rand"
	"encoding/hex"
)

// randHex returns n random bytes hex-encoded (2n chars), used to make run IDs
// unique even when two runs start in the same second. Falls back to a fixed
// suffix only if the system RNG fails (which would be catastrophic elsewhere
// too) — a non-unique-but-present suffix is better than a panic in a validation
// helper.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "00000000"[:2*n]
	}
	return hex.EncodeToString(b)
}
