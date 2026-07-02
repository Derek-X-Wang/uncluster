package ca

import (
	"errors"
	"fmt"
	"os"
)

// ErrInvalidInput classifies a Sign failure caused by bad caller input — a
// malformed pubkey, a certificate supplied where a raw pubkey is required, an
// invalid validity window, a missing principal, or a missing KeyID — as opposed
// to a server-side signing failure. Every input-validation error returned by
// Sign wraps this sentinel, so callers classify with errors.Is instead of
// matching the human-readable message text. That keeps the CA's error wording
// out of its interface: the cert-signing handler maps ErrInvalidInput to 400
// and everything else to 500, and a future message reword cannot silently
// reclassify a request.
var ErrInvalidInput = errors.New("ca: invalid input")

// loosePerm is returned when a file has overly permissive access controls.
type loosePerm struct {
	path string
	mode os.FileMode // 0 on Windows (mode bits not applicable)
}

func (e *loosePerm) Error() string {
	if e.mode != 0 {
		return fmt.Sprintf("ca: %s has mode %#o with group/world bits set; refusing (must be 0600)", e.path, e.mode)
	}
	return fmt.Sprintf("ca: %s has loose permissions (accessible to non-admin accounts); refusing", e.path)
}
