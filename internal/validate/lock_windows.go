//go:build windows

package validate

import "golang.org/x/sys/windows"

// processAlive reports whether a process with the given PID exists on Windows.
// OpenProcess with a query-limited access right succeeds for a live process and
// fails once it has exited, which is the signal we want for stale-lock
// detection. A non-positive PID is never alive.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	// A handle to a process that has exited can still open briefly; confirm it
	// has not terminated by checking its exit code is STILL_ACTIVE.
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259 // STILL_ACTIVE
	return code == stillActive
}
