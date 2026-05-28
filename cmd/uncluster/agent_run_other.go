//go:build !windows

package main

// runAsWindowsService is a no-op on non-Windows platforms. systemd and
// launchd do not require an SCM-style control-handler handshake — having
// the process alive is enough. Returning (false, nil) hands control back
// to main so the cobra root executes as usual. See #88.
func runAsWindowsService() (handled bool, err error) {
	return false, nil
}
