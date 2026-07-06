//go:build linux

package gatekeeper

import "syscall"

// stNoexec is the statfs f_flags bit set when a filesystem is mounted noexec
// (ST_NOEXEC in <sys/statvfs.h>; Linux populates statfs f_flags since 2.6.36).
const stNoexec = 0x0008

// payloadDirIsNoexec reports whether dir is on a noexec mount. known is false
// when the mount flags cannot be read (statfs error), so the caller degrades to
// "not asserted" rather than a false fail.
func payloadDirIsNoexec(dir string) (noexec bool, known bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, false
	}
	return st.Flags&stNoexec != 0, true
}
