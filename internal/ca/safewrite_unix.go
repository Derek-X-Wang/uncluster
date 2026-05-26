//go:build !windows

package ca

import (
	"fmt"
	"os"
	"syscall"
)

// openExclusiveNoFollow on Unix uses O_NOFOLLOW so that even a race-planted
// symlink at path can't be followed. O_EXCL alone refuses an existing entry,
// but O_NOFOLLOW makes the refusal explicit when the entry is a symlink and
// closes the (admittedly tiny) TOCTOU window between MkdirAll and Open.
func openExclusiveNoFollow(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,
		mode)
}

// ensureTightDir on Unix refuses a parent directory whose POSIX mode permits
// group or world access. A 0o600 file inside a 0o755 dir is still replaceable
// by anyone with write access to that dir (rename/unlink + recreate), so the
// dir mode is part of the CA-key threat model — not just the file mode.
//
// MkdirAll(dir, 0o700) creates the dir tight when absent; this check guards
// the case where the dir was pre-created at default umask 0o755 by some
// other process before bootstrap ran (the exact scenario in issue #38).
func ensureTightDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("ca: stat parent dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("ca: parent %s is not a directory", dir)
	}
	if extra := info.Mode().Perm() & 0o077; extra != 0 {
		return fmt.Errorf("ca: parent dir %s has loose mode %#o; refusing (need 0700)",
			dir, info.Mode().Perm())
	}
	return nil
}
