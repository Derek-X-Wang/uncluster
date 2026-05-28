//go:build windows

package ca

import (
	"os"
)

// openReadOnlyNoFollow on Windows opens path for reading. O_NOFOLLOW has
// no portable Windows analog — symlink semantics on NTFS differ from
// POSIX (reparse points + privilege-gated traversal), and the practical
// defence is the file's DACL applied by restrictFileACL. This function
// preserves the cross-platform call site shape and exists primarily so
// the unix path can use O_NOFOLLOW where it actually matters.
func openReadOnlyNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// checkFileModeFromFD on Windows is a no-op for POSIX mode bits — those
// don't gate access on NTFS. The DACL applied at write time by
// restrictFileACL (SYSTEM + Administrators only) is what restricts
// access, and checkFileACL (called by the load path against the file
// path) inspects that DACL. We keep this function for symmetry with
// the unix build so the LoadPrivateFromDisk call sequence stays
// platform-agnostic in the caller.
func checkFileModeFromFD(_ *os.File) error {
	return nil
}

// checkParentDirSafe on Windows is a no-op: NTFS dir permissions are
// inherited via ACLs, not POSIX mode bits, and the file-level ACL
// applied by restrictFileACL (SYSTEM + Administrators) is the
// authoritative protection. We keep this function for cross-platform
// call-site symmetry so the loader's body reads the same on both
// platforms.
func checkParentDirSafe(_ string) error {
	return nil
}
