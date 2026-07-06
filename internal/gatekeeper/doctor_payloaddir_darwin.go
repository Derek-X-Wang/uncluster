//go:build darwin

package gatekeeper

import "syscall"

// mntNoexec is the mount flag set when a filesystem disallows execution
// (MNT_NOEXEC in <sys/mount.h>).
const mntNoexec = 0x00000004

// payloadDirIsNoexec reports whether dir is on a noexec mount. known is false
// when the mount flags cannot be read (statfs error), so the caller degrades to
// "not asserted" rather than a false fail.
func payloadDirIsNoexec(dir string) (noexec bool, known bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, false
	}
	return st.Flags&mntNoexec != 0, true
}
