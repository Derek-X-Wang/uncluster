//go:build !windows

package ca

import (
	"fmt"
	"os"
	"syscall"
)

// openReadOnlyNoFollow opens path for reading with O_NOFOLLOW so a symlink
// at path causes the open to fail rather than resolve to the symlink's
// target. Closing the returned file is the caller's responsibility.
//
// Why O_NOFOLLOW matters here: the stdlib Stat/Open functions resolve
// symlinks transparently. If an attacker plants a symlink at the CA-key
// path pointing at attacker-controlled bytes, a naive Open returns the
// attacker's bytes despite any path-based perm check. O_NOFOLLOW refuses
// the open entirely (ELOOP) so the load fails cleanly instead of
// silently swapping the key.
func openReadOnlyNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// checkFileModeFromFD validates POSIX mode bits read from an already-open
// file descriptor (NOT from the path). This is what makes the load TOCTOU-
// proof: f.Stat() returns the inode-attached mode of the file you are
// holding open, which is what you will then read from. A path-based Stat
// (the pre-fix shape) could be staring at a different inode if the
// attacker swapped the directory entry between calls.
//
// Returns &loosePerm with the actual mode if any group/world bit is set.
func checkFileModeFromFD(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("ca: fstat: %w", err)
	}
	if extra := info.Mode().Perm() & 0o077; extra != 0 {
		return &loosePerm{path: f.Name(), mode: info.Mode().Perm()}
	}
	return nil
}

// checkParentDirSafe verifies the parent directory of `path` is not
// world/group-writable AND is owned by the current process's effective
// UID. The latter catches the case where the directory was pre-created
// by another principal (say, an install script running as a different
// user) — a file inside it can be replaced by that other principal even
// if file-level perms are 0600.
//
// Path-resolution note: we use os.Stat on the parent dir's PATH (not an
// fd-stat). That is acceptable here because the directory's identity
// matters for trust, not its bytes — and we only act on the result by
// refusing to proceed. We then open the FILE with O_NOFOLLOW relative
// to the trusted parent in the caller. (Doing an *fd*-relative open
// via openat() would harden this further, but Go's stdlib does not
// expose openat directly; for this slice the dir-stat + O_NOFOLLOW pair
// is sufficient against the documented attack class — directory swap
// attacks require root and at that point the threat model has bigger
// problems.)
func checkParentDirSafe(path string) error {
	dir := parentDir(path)
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
	// Owner UID check: must equal the process's effective UID. Tests
	// running as a non-root user that didn't create the dir will fail
	// here — which is exactly the protection we want for production but
	// is annoying for testing. The test in safeopen_unix_test.go uses
	// MkdirTemp + os.Chmod so the dir is created with the right owner.
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// On platforms where Sys() doesn't return *syscall.Stat_t we
		// skip the owner check (best-effort). On linux/darwin it does.
		return nil
	}
	if euid := os.Geteuid(); uint32(euid) != st.Uid {
		return fmt.Errorf("ca: parent dir %s owned by uid=%d, expected %d", dir, st.Uid, euid)
	}
	return nil
}

// parentDir returns the directory portion of path. Equivalent to
// filepath.Dir but kept local to avoid an extra import when this file
// is the only caller.
func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
