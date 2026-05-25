//go:build !windows

package ca

import "os"

// restrictFileACL on Unix is a no-op — the POSIX mode 0600 applied at write
// time is sufficient. On Windows this function applies a DACL via SetNamedSecurityInfo.
func restrictFileACL(_ string) error { return nil }

// checkFileACL on Unix checks POSIX mode bits (group/world must be unset).
// Returns an error when the file has loose permissions.
func checkFileACL(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if extra := info.Mode().Perm() & 0o077; extra != 0 {
		return &loosePerm{path: path, mode: info.Mode().Perm()}
	}
	return nil
}
