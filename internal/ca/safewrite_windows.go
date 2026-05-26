//go:build windows

package ca

import "os"

// openExclusiveNoFollow on Windows uses O_CREATE|O_EXCL. O_NOFOLLOW has no
// Windows equivalent in the syscall surface Go exposes, and creating symlinks
// on Windows requires SeCreateSymbolicLink privilege (typically admin), so
// the symlink-attack class is far narrower. The O_EXCL refusal-on-existing
// path still prevents overwrite of any pre-planted entry.
func openExclusiveNoFollow(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
}

// ensureTightDir on Windows is a no-op: POSIX mode bits don't gate access.
// The CA-key file's DACL (set by restrictFileACL after write) is the actual
// access control. Restricting the parent dir's DACL would also be valuable
// but is out of scope for issue #38 (which targets the symlink-follow CVE
// shape, not Windows ACL hardening of the parent dir).
func ensureTightDir(_ string) error { return nil }
