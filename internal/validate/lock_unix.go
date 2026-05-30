//go:build !windows

package validate

import "syscall"

// processAlive reports whether a process with the given PID exists. On Unix,
// signal 0 performs error-checking without actually sending a signal: nil or
// EPERM means the process exists (EPERM = exists but not ours to signal);
// ESRCH means it is gone. A non-positive PID is never alive.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return err == syscall.EPERM
}
